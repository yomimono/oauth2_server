module Make(Random : Mirage_random.S) = struct

  let challenge verifier =
    Mirage_crypto.Hash.SHA256.(digest (Cstruct.of_string verifier)) |> Cstruct.to_string |> Base64.encode_string

  let verifier () =
    Random.generate 32 |> Cstruct.to_string |> Base64.encode_string

end
