using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace AuthenticationJWT.Controllers
{
    [RoutePrefix("api")]
    public class DefaultController : ApiController
    {
        [HttpPost, Route("login")]
        public HttpResponseMessage Login(User user)
        {
            User u = new UserRepository().GetUser(user.Username);
            if (u == null)
                return Request.CreateResponse(HttpStatusCode.NotFound,
                     "The user was not found.");

            bool credentials = u.Password.Equals(user.Password);

            if (!credentials) return Request.CreateResponse(HttpStatusCode.Forbidden,
                "The username/password combination was wrong.");

            return Request.CreateResponse(HttpStatusCode.OK,
                 TokenManager.GenerateToken(user.Username));
        }

        [HttpGet, Route("validate")]
        public HttpResponseMessage Validate(string username)
        {
            try
            {
                var token = Request.Headers.Authorization.Parameter;

                bool exists = new UserRepository().GetUser(username) != null;

                if (!exists) return Request.CreateResponse(HttpStatusCode.NotFound,
                     "The user was not found.");

                string tokenUsername = TokenManager.ValidateToken(token);

                if (username.Equals(tokenUsername))
                    return Request.CreateResponse(HttpStatusCode.OK, username);

                return Request.CreateResponse(HttpStatusCode.Unauthorized, "invalid token");
            }catch(Exception ex)
            {
                return Request.CreateResponse(HttpStatusCode.Unauthorized, ex.Message);
            }
        }
    }
}