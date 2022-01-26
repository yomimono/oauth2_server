module Make(Random : Mirage_random.S) = struct

  let alphabet = Base64.uri_safe_alphabet

  let challenge verifier =
    Base64.encode_string ~pad:false ~alphabet @@
    Cstruct.to_string @@
    Mirage_crypto.Hash.SHA256.(digest (Cstruct.of_string verifier))

  let verifier () =
    Random.generate 32 |> Cstruct.to_string |> Base64.(encode_string ~pad:false ~alphabet:uri_safe_alphabet)

end
