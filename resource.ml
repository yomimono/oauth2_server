let auth_url = Uri.of_string "https://api.etsy.com/v3/public/oauth/token"
let default_access_expiration = Ptime.Span.of_int_s 3600
let requested_scopes = String.concat " " ["listings_r"; "listings_w"]
module Verify_url = struct
  let host = "etsy.com"
  let path = "/oauth/connect"
  let scheme = "https"
end
