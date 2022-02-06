open Lwt.Infix

module Make(Clock : Mirage_clock.PCLOCK)(Kv : Mirage_kv.RW) = struct
  let older_than kv ptime =
    Kv.list kv Mirage_kv.Key.empty >>= function
    | Error e ->
      Logs.err (fun f -> f "error listing /: %a" Kv.pp_error e);
      Lwt.return []
    | Ok l ->
      (* for any entry in the list where we can't get last_modified info,
       * or the last_modified isn't parseable,
       * return true -- if we don't, these entries will just stick around forever *)
      Lwt_list.filter_p (fun (name, value_or_dict) ->
          Kv.last_modified kv (Mirage_kv.Key.v name) >>= function
          | Error _ -> Lwt.return true
          | Ok (d, ps) ->
            try
              let write_time = Ptime.v (d, ps) in
              Lwt.return @@ Ptime.is_earlier ~than:ptime write_time
            with
            | Invalid_argument _ -> Lwt.return true
        ) l

  let prune kv expiration_span =
    let now = Clock.now_d_ps () |> Ptime.v in
    match Ptime.sub_span now expiration_span with
    | None ->
      Logs.err (fun f -> f "failed to calculate cutoff time for recycling items");
      Lwt.return_unit
    | Some cutoff ->
      Logs.debug (fun f -> f "deleting entries with no updates since %a" Ptime.pp cutoff);
      older_than kv cutoff >>= fun to_prune ->
      Logs.debug (fun f -> f "deleting %d expired entries" (List.length to_prune));
      Lwt_list.iter_p (fun (item, _) ->
          Kv.remove kv (Mirage_kv.Key.v item) >>= function
          | Error e -> Logs.err (fun f -> f "error removing item to be pruned: %s" item);
            Lwt.return_unit
          | Ok () -> Lwt.return_unit
        ) to_prune

end
