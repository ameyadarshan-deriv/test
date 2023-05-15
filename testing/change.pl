sub backend_setup {
    my ($log) = @_;
    my $backend_setup_finished = 511;

    $redis->get(
        'web_socket_proxy::backends',
        sub {
            my ($redis, $err, $backends_str) = @_;
            if ($err) {
                $log->error("Error reading backends from master redis: $err");
            }
            if ($backends_str) {
                $log->info("Found rpc backends in redis, applying.");
                try {
                    my $backends = decode_json_utf8($backends_str);
                    for my $method (keys %$backends) {
                        my $backend = $backends->{$method} // 'default';
                        $backend = 'default' if $backend eq 'rpc_redis';
                        if (exists $WS_ACTIONS->{$method} and ($backend eq 'default' or exists $WS_BACKENDS->{$backend})) {
                            $WS_ACTIONS->{$method}->{backend} = $backend;
                        } else {
                            $log->warn("Invalid  backend setting ignored: <$method $backend>");
                        }
                    }
                    $backend_setup_finished = 1;
                } catch ($e) {
                    $log->error("Error applying backends from master: $e");
                }
            } else {    # there is nothing saved in redis yet.
                $backend_setup_finished = 1;
            }
        });
    for (my $seconds = 0.5; $seconds <= 4; $seconds *= 2) {
        my $timeout = 0;
        Mojo::IOLoop->timer($seconds => sub { ++$timeout });
        Mojo::IOLoop->one_tick while !($timeout or $backend_setup_finished);
        last if $backend_setup_finished;
        $log->error("Timeout $seconds sec. reached when trying to load backends from master redis.");
    }
    unless ($backend_setup_finished) {
        die 'Failed to read rpc backends from master redis. Please retry after ensuring that master redis is started.';
    }

}

sub startup {
    my $app = shift;

    $app->moniker('websocket');
    $app->plugin('Config' => {file => $ENV{WEBSOCKET_CONFIG} || '/etc/rmg/websocket.conf'});

    my $skip_redis_connection_check = $ENV{WS_SKIP_REDIS_CHECK} // $app->config->{skip_redis_connection_check};

    check_connections() unless $skip_redis_connection_check;    ### Raise and check redis connections

    Mojo::IOLoop->singleton->reactor->on(
        error => sub {
            my (undef, $err) = @_;
            $log->error("EventLoop error: $err");
        });

    $log->info("Binary.com Websockets API");
    $log->infof("Mojolicious Mode is %s", $app->mode);
    $log->infof("Log Level        is %s", $log->adapter->can('level') ? $log->adapter->level : $log->adapter->{log_level});

    apply_usergroup $app->config->{hypnotoad}, sub {
        $log->info(@_);
    };
    $node_config = YAML::XS::LoadFile('/etc/rmg/node.yml');
    # binary.com plugins
    push @{$app->plugins->namespaces}, 'Binary::WebSocketAPI::Plugins';
    $app->plugin('Introspection' => {port => 0});
    $app->plugin('RateLimits');
    $app->plugin('Longcode');

    $app->hook(
        before_dispatch => sub {
            my $c = shift;

            return unless $c->tx;

            my $lang = defang($c->param('l'));
            if ($lang =~ /^\D{2}(_\D{2})?$/) {
                $c->stash(language => uc $lang);
                $c->res->headers->header('Content-Language' => lc $lang);
            } else {
                # default to English if not valid language
                $c->stash(language => 'EN');
                $c->res->headers->header('Content-Language' => 'en');
            }

            if ($c->req->param('debug')) {
                $c->stash(debug => 1);
            }

            my $app_id = $c->app_id;
            return $c->render(
                json   => {error => 'InvalidAppID'},
                status => 401
            ) unless $app_id;

            return $c->render(
                json   => {error => 'AccessRestricted'},
                status => 403
            ) if exists $BLOCK_APP_IDS{$app_id};

            return $c->render(
                json   => {error => 'AccessRestricted'},
                status => 403
            ) if first { $app_id == $_ } $APPS_BLOCKED_FROM_OPERATION_DOMAINS{$node_config->{node}->{operation_domain} // ''}->@*;

            my $request_origin = $c->tx->req->headers->origin // '';
            $request_origin = 'https://' . $request_origin unless $request_origin =~ /^https?:/;
            my $uri = URI->new($request_origin);
            return $c->render(
                json   => {error => 'AccessRestricted'},
                status => 403
            ) if exists $BLOCK_ORIGINS{$uri->host};

            my $client_ip = $c->client_ip;

            my $brand_name = defang($c->req->param('brand'))            // '';
            my $brand      = (first { $_ eq $brand_name } VALID_BRANDS) // DEFAULT_BRAND;

            if ($c->tx and $c->tx->req and $c->tx->req->headers->header('REMOTE_ADDR')) {
                $client_ip = $c->tx->req->headers->header('REMOTE_ADDR');
            }

            my $user_agent = $c->req->headers->header('User-Agent');

            # We'll forward the domain for constructing URLs such as cashier. Note that we are
            # not guaranteed to have referrer information so the stash value may not always
            # be set.
            if (my $domain = $c->req->headers->header('Origin')) {
                my $name = $brand;
                if (my ($domain_without_prefix) = $domain =~ m{^(?:https://)?\S+($name\.\S+)$}) {
                    $c->stash(domain => $domain_without_prefix);
                }
            }

            $c->stash(
                server_name          => $c->server_name,
                client_ip            => $client_ip,
                referrer             => $c->req->headers->header('Origin'),
                country_code         => $c->country_code,
                landing_company_name => $c->landing_company_name,
                user_agent           => $user_agent,
                ua_fingerprint       => md5_hex(($app_id // 0) . ($client_ip // '') . ($user_agent // '')),
                ($app_id) ? (source => $app_id) : (),
                brand       => $brand,
                source_type => '',       # Source type will be populated with a first RPC response
            );
        });

    $app->plugin(
        'Mojolicious::Plugin::ClientIP::Pluggable',
        analyze_headers => [qw/cf-pseudo-ipv4 cf-connecting-ip true-client-ip/],
        restrict_family => 'ipv4',
        fallbacks       => [qw/rfc-7239 x-forwarded-for remote_address/]);
    $app->plugin('Binary::WebSocketAPI::Plugins::Helpers');

    my $actions = Binary::WebSocketAPI::Actions::actions_config();

    my $category_timeout_config = _category_timeout_config();
    %RPC_ACTIVE_QUEUES = map { $_ => 1 } @{$app->config->{rpc_active_queues} // []};
    my $backend_rpc_redis = redis_rpc();
    $WS_BACKENDS = {
        rpc_redis => {
            type                     => 'consumer_groups',
            redis                    => $backend_rpc_redis,
            timeout                  => $app->config->{rpc_queue_response_timeout},
            category_timeout_config  => $category_timeout_config,
            queue_separation_enabled => $app->config->{rpc_queue_separation_enabled},
        },
    };

    my $json = JSON::MaybeXS->new;
    for my $action (@$actions) {
        my $action_name = $action->[0];
        my $f           = '/home/git/regentmarkets/binary-websocket-api/config/v3';
        my $schema_send = $json->decode(path("$f/$action_name/send.json")->slurp_utf8);

        my $action_options = $action->[1] ||= {};
        $action_options->{schema_send} = $schema_send;
        $action_options->{stash_params} ||= [];
        push @{$action_options->{stash_params}}, qw( language country_code );
        push @{$action_options->{stash_params}}, 'token' if $schema_send->{auth_required};

        $WS_ACTIONS->{$action_name} = $action_options;
    }

    $app->helper(
        'app_id' => sub {
            my $c = shift;
            return undef unless $c->tx;
            my $possible_app_id = $c->req->param('app_id');
            if (defined($possible_app_id) && $possible_app_id =~ /^(?!0)[0-9]{1,19}$/) {
                return $possible_app_id;
            }
            return undef;
        });

    $app->helper(
        'rate_limitations_key' => sub {
            my $c = shift;
            return "rate_limits::closed" unless $c && $c->tx;

            my $app_id   = $c->app_id;
            my $login_id = $c->stash('loginid');
            return "rate_limits::authorised::$app_id/$login_id" if $login_id;

            my $ip = $c->client_ip;
            if ($ip) {
                # Basic sanitisation: we expect IPv4/IPv6 addresses only, reject anything else
                $ip =~ s{[^[:xdigit:]:.]+}{_}g;
            } else {
                DataDog::DogStatsd::Helper::stats_inc('bom_websocket_api.unknown_ip.count');
                $ip = 'UNKNOWN';
            }

            # We use empty string for the default UA since we'll be hashing anyway
            # and our highly-trained devops team can spot an md5('') from orbit
            my $user_agent = $c->req->headers->header('User-Agent') // '';
            my $client_id  = $ip . ':' . md5_hex($user_agent);
            return "rate_limits::unauthorised::$app_id/$client_id";
        });

    $app->plugin(
        'web_socket_proxy' => {
            binary_frame => \&Binary::WebSocketAPI::v3::Wrapper::DocumentUpload::document_upload,
            # action hooks
            before_forward => [
                \&Binary::WebSocketAPI::Hooks::start_timing,             \&Binary::WebSocketAPI::Hooks::before_forward, #rate limiting here
                \&Binary::WebSocketAPI::Hooks::ignore_queue_separations, \&Binary::WebSocketAPI::Hooks::introspection_before_forward,
                \&Binary::WebSocketAPI::Hooks::assign_ws_backend,        \&Binary::WebSocketAPI::Hooks::check_app_id
            ],
            before_call => [
                \&Binary::WebSocketAPI::Hooks::log_call_timing_before_forward, \&Binary::WebSocketAPI::Hooks::add_app_id,
                \&Binary::WebSocketAPI::Hooks::add_log_config,                 \&Binary::WebSocketAPI::Hooks::add_brand,
                \&Binary::WebSocketAPI::Hooks::start_timing
            ],
            before_get_rpc_response  => [\&Binary::WebSocketAPI::Hooks::log_call_timing],
            after_got_rpc_response   => [\&Binary::WebSocketAPI::Hooks::log_call_timing_connection, \&Binary::WebSocketAPI::Hooks::error_check],
            before_send_api_response => [
                \&Binary::WebSocketAPI::Hooks::add_req_data,      \&Binary::WebSocketAPI::Hooks::start_timing,
                \&Binary::WebSocketAPI::Hooks::output_validation, \&Binary::WebSocketAPI::Hooks::add_call_debug,
                \&Binary::WebSocketAPI::Hooks::introspection_before_send_response
            ],
            after_sent_api_response => [\&Binary::WebSocketAPI::Hooks::log_call_timing_sent, \&Binary::WebSocketAPI::Hooks::close_bad_connection],

            # main config
            base_path         => '/websockets/v3',
            stream_timeout    => 120,
            max_connections   => 100000,
            max_response_size => 600000,                                                # change and test this if we ever increase ticks history count
            opened_connection => \&Binary::WebSocketAPI::Hooks::on_client_connect,
            finish_connection => \&Binary::WebSocketAPI::Hooks::on_client_disconnect,
            before_shutdown   => \&Binary::WebSocketAPI::v3::Wrapper::Streamer::send_deploy_notification,

            # helper config
            actions         => $actions,
            backends        => $WS_BACKENDS,
            default_backend => $app->config->{default_backend},
            # Skip check sanity to password fields
            skip_check_sanity => qr/password/,
            rpc_failure_cb    => sub {
                my ($c, $res, $req_storage, $error) = @_;
                if (
                       defined $error
                    && ref $error eq 'HASH'
                    && (
                        !exists $error->{type}
                        || (   $error->{type} ne "Timeout"
                            && $error->{type} ne "WrongResponse")))
                {
                    my $details = 'URL: ' . ($req_storage->{req_url} // 'n/a');
                    if ($error->{code} || $error->{message}) {
                        $details .= ', code: ' . ($error->{code} // 'n/a') . ', response: ' . $error->{message} // 'n/a';
                    }
                    # we don't log WrongResponse and Timeouts as we have metrics for them
                    # this exception should be removed when we have properly
                    # handled CallError
                    $log->info(($error->{type} // 'n/a') . " [" . $req_storage->{msg_type} . "], details: $details");
                }
                DataDog::DogStatsd::Helper::stats_inc(
                    "bom_websocket_api.v_3.rpc.error.count",
                    {
                        tags => [
                            sprintf("rpc:%s",        $req_storage->{method}),
                            sprintf("source:%s",     $c->stash('source')),
                            sprintf("error_type:%s", ($error->{type} // 'UnhandledErrorType')),
                            sprintf("stream:%s",
                                ($req_storage->{msg_group} // Mojo::WebSocketProxy::Backend::ConsumerGroups::DEFAULT_CATEGORY_NAME()))]});
                return undef;
            },
        });

    get_redis_value_setup('app_id::diverted',           $log);
    get_redis_value_setup('app_id::blocked',            $log);
    get_redis_value_setup('origins::blocked',           $log);
    get_redis_value_setup('domain_based_apps::blocked', $log);
    get_redis_value_setup('rpc::logging',               $log);
    backend_setup($log);

    return;
}

sub update_apps_blocked_from_operation_domain {
    my ($apps_blocked_json) = @_;
    my $json = JSON::MaybeXS->new;
    %APPS_BLOCKED_FROM_OPERATION_DOMAINS = %{$json->decode($apps_blocked_json)};
}
