import { promisify } from 'util';
import jwt from 'jsonwebtoken';

import { serialize } from 'cookie';
import Redis from 'ioredis';

let NEXT_PUBLIC_SAASBOX_DOMAIN = process.env.NEXT_PUBLIC_SAASBOX_DOMAIN ? process.env.NEXT_PUBLIC_SAASBOX_DOMAIN : "http://saasbox.net:8081";
let LOGIN_URL = NEXT_PUBLIC_SAASBOX_DOMAIN + "/login";
let JWT_ROUTE = "/api/user-token-otc";
let JWT_URL = NEXT_PUBLIC_SAASBOX_DOMAIN + JWT_ROUTE;
// Redis access string, e.g. "rediss://:<values>.upstash.io:32833";
let SAASBOX_REDIS = process.env.SAASBOX_REDIS

// Saves state that user state is changed and JWT needs refreshing.
// user state changed webhook from SaaSBox calls this.
export async function userStateChanged(req, res) {
  let client = new Redis(SAASBOX_REDIS);
  if (req.body.id) {
    await client.set(req.body.id, true);
  }
}

// Tells whether the user state has changed and JWT needs refreshing.
// Call this to re-do token.
async function hasUserStateChanged(user_struct) {
  let client = new Redis(SAASBOX_REDIS);
  let result = await client.get(user_struct.id)
  if (result == "true") {
    await client.del(user_struct.id);
    return true;
  } else {
    return false;
  }
}

/*
 * Same logic as in withSboxAuth, somehow refactoring breaks things (should pass handler as arg?)
 * Fetch new JWT using user id to refresh data structure.
 * Set cookie with JWT
 * Return user struct to set req, and call final handler.
 */
async function refreshSession(ctx, req, res, otc) {
  let token;
  let user_struct;

  try {
    token = await fetchJWT(JWT_URL, otc);
    if (token) {
      // Verify JWT
      user_struct = await validateToken(req, token);
      ctx.res.setHeader(
        "Set-Cookie",
        serialize("user_auth", token, {
          // very secure cookies options
          httpOnly: true,
          sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
          secure: process.env.NODE_ENV === 'production' ? true : false,
          maxAge: process.env.NODE_ENV === 'production' ? 51843000 : 60*60 // 1 hour (unit: seconds)
        })
      );
      return user_struct;
    } else {
      //throw new Error("Refreshing user token has failed. Token not fetched properly or is invalid.")
    }
  } catch (err) {
    console.error(err);
    //throw new Error(err);
  }
}

// Use as an API handler, the component posts to it from a form to logout.
export function LogoutApi(req, res) {
  let options = {
    path: "/",
    expires: new Date(0)  // Set to 1970 valid date format.
  }
  try {
    // Expire auth cookie and redirect to "/"
    res.setHeader('Set-Cookie', serialize("user_auth", "deleted", options))
    res.redirect("/")
  } catch (err) {
    console.log("Failed to expire auth cookie:", err);
  }
}

//
// Init object:
// User must configure NEXT_PUBLIC_SAASBOX_DOMAIN
//
export function init(config) {
  if (config.NEXT_PUBLIC_SAASBOX_DOMAIN == undefined) {
    if (process.env.NEXT_PUBLIC_SAASBOX_DOMAIN) {
      console.log("No SaaSBox domain provided, using environment variable:", process.env.NEXT_PUBLIC_SAASBOX_DOMAIN);
      NEXT_PUBLIC_SAASBOX_DOMAIN = process.env.NEXT_PUBLIC_SAASBOX_DOMAIN;
    }
    console.error("You must set your SaaSBox domain in format [https://yourdomain.saasbox.net] in order to use this authentication method.")
    return false;
  } else {
    NEXT_PUBLIC_SAASBOX_DOMAIN = config.NEXT_PUBLIC_SAASBOX_DOMAIN;
  }

  // This is optional, default is more correct than any user supplied.
  if (config.LOGIN_URL) {
    LOGIN_URL = config.LOGIN_URL;
  }

  // This is optional, default is more correct than any user supplied.
  if (config.JWT_ROUTE)
    JWT_ROUTE = config.JWT_ROUTE;
}

// Get JWT from main site in exchange of one time code.
async function fetchJWT(url, otc) {
  let result;
  let headers = new Headers();
  headers.set('Authorization',
    'Basic ' + Buffer.from(process.env.SAASBOX_APP_ID + ":" + process.env.SAASBOX_API_KEY).toString('base64'));
  headers.set('Content-Type', 'application/json');
  try {
    // TODO: Add Bearer token here.
    let response = await fetch(JWT_URL, {
      body: JSON.stringify({ otc: otc }),
      headers: headers,
      method: 'POST'
    });
    if (response.ok) {
      result = await response.json();
      // Response ok and JWT
      if (result.jwt) {
        return result.jwt
        // Response ok but server returned error
      } else if (result.error) {
        throw new Error(result.error)
        // Response ok but no JWT, something else we dont want occured
      } else {
        throw new Error("Fetching User JWT for OTC failed.")
      }
      // Response not OK
    } else {
      throw new Error("Fetching User JWT for OTC failed.");
    }
  } catch (err) {
    console.error(err);
    throw new Error(err);
  }
}

async function getOTC(req) {
  const { nextUrl: { search } } = req;
  const urlSearchParams = new URLSearchParams(search);
  let otc = await urlSearchParams.get('otc');
  return otc;
}

// Unused, can't set cookie and later use same res to do next(), has to be 
// all at once.
async function setCookieJWT(req, res, token) {
  // Set user auth cookie with JWT
  return res.cookie('user_auth', token, {
    httpOnly: true,
    sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
    secure: process.env.NODE_ENV === 'production' ? true : false,
    maxAge: 1800000, // 30 minutes
  });
}


/*
 * Returns decoded user from already authenticated JWT cookie, does this for
 * getServerSideProps.
 */

// TODO: Verify token expired or not, verify contents.
async function validateToken(NextRequest, token) {
  // Verify token
  const decoded = await promisify(jwt.verify)(token, process.env.SAASBOX_JWT_SECRET);

  try {
    if (decoded) {
       //console.log("Decoded user, TODO: Validate expiry:", decoded);
      return decoded;
    } else {
      throw Error("JWT invalid, sign in again.")
    }
  } catch (err) {
    throw new Error(err);
  }
}

const redirect = function (url) {
  return {
    redirect: {
      destination: url
    }
  }
}

// Only for getServerSideProps which gets a ctx argument.
// NOTE: if cookie is valid, otc is skipped.
const withSboxAuth = (handler) => {
  return async (ctx) => {
    let req = ctx.req;
    let res = ctx.res;
    //console.log("ctx:", ctx);
    let otc = ctx.query.otc;
    let token;
    let user_struct = {};

    try {
      if (req.cookies && req.cookies.user_auth) {
        token = req.cookies.user_auth;
        //console.log("Found JWT cookie, validating.")
        user_struct = await validateToken(req, token);
        // Auth OK, set user
        //console.log("Setting valid user")
        if (await hasUserStateChanged(user_struct)) {
          // Same user but updated struct.
          //console.log("Calling refresh session with one in query params, or existing otc in JWT\n")
          user_struct = await refreshSession(ctx, req, res, otc ? otc : user_struct.otc);
        }
        req.user = user_struct;
        // Go to next
        return handler(ctx.req, ctx.res);
      } else {
        //console.log("No JWT cookie, see if OTC is there.")
        if (otc) {
          // Get JWT
          //console.log("OTC is there, fetching JWT with otc=", otc)
          token = await fetchJWT(JWT_URL, otc);
          if (token) {
            // Verify JWT
            user_struct = await validateToken(req, token);
            // Set Cookie - this doesn't work, cant use returned cookie
            // await setCookieJWT(req, res, token);

            // Auth OK, set user:
            //console.log("Setting valid user:", user_struct)
            req.user = user_struct;
            // Go to next
            //console.log("Set the cookie with JWT info")
            //res.setHeader("Set-Cookie", "foo=bar");
            ctx.res.setHeader(
              "Set-Cookie",
              serialize("user_auth", token, {
                // very secure cookies options
                httpOnly: true,
                sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
                secure: process.env.NODE_ENV === 'production' ? true : false,
                maxAge: process.env.NODE_ENV === 'production' ? 51843000 : 24*60*60 // 60 days or 1 day
              })
            );
            return handler(ctx.req, ctx.res);
            /*return res.cookie("user_auth", token, {
              httpOnly: true,
              sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
              secure: process.env.NODE_ENV === 'production' ? true : false,
              maxAge: 1800000, // 30 minutes
            });*/
          }
        } else {
          // No OTC, No Auth. Redirect to main app for authentication
          //console.log("No JWT, no cookie, no OTC, redirecting.")
          //return res.redirect(LOGIN_URL);
          return redirect(LOGIN_URL);
        }
      }
      // All errors in try caught here. Ends up in auth redirect.
    } catch (error) {
      // We could handle this by showing auth_error for 5 seconds
      // Then redirecting to saasbox.
      console.log(error);
      console.log("there was error, calling handler with error.")
      return handler(ctx.req, ctx.res);
    }
  }
}

export default withSboxAuth;
