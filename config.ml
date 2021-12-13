open Mirage

(* original ACME code provided by https://github.com/roburio/unipi ,
 * adapted for this project by yomimono *)

let hostname =
  let doc = Key.Arg.info ~doc:"Host name." ["hostname"] in
  Key.(create "hostname" Arg.(opt (some string) None doc))

let production =
  let doc = Key.Arg.info ~doc:"Let's encrypt production environment." ["production"] in
  Key.(create "production" Arg.(opt bool false doc))

let cert_seed =
  let doc = Key.Arg.info ~doc:"Let's encrypt certificate seed." ["cert-seed"] in
  Key.(create "cert_seed" Arg.(opt (some string) None doc))

let account_seed =
  let doc = Key.Arg.info ~doc:"Let's encrypt account seed." ["account-seed"] in
  Key.(create "account_seed" Arg.(opt (some string) None doc))

let email =
  let doc = Key.Arg.info ~doc:"Let's encrypt E-Mail." ["email"] in
  Key.(create "email" Arg.(opt (some string) None doc))

let packages = [
  package "fmt";
  package "cohttp-mirage";
  package "tls-mirage";
  package "magic-mime";
  package "logs";
  package ~min:"0.4.0" "letsencrypt";
]

let stack = generic_stackv4v6 default_network

let conduit_ = conduit_direct ~tls:true stack
let http_srv = cohttp_server conduit_
let http_cli = cohttp_client (resolver_dns stack) conduit_

let () =
  let keys = Key.([
      v hostname; v production; v cert_seed;
      v account_seed; v email;
    ])
  in
  register "oauth2" [
    foreign
      ~keys
      ~packages
      "Unikernel.Main"
      (http_client @-> http @-> pclock @-> time @-> job)
    $ http_cli $ http_srv
    $ default_posix_clock
    $ default_time
  ]
