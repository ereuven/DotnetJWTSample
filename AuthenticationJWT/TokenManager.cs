/*
 * https://www.red-gate.com/simple-talk/dotnet/net-development/jwt-authentication-microservices-net/
 */

using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace AuthenticationJWT
{
    public static class TokenManager
    {
        private static SymmetricSecurityKey _securityKey { get; }
        private const string K1 = "k1value";

        static TokenManager()
        {
            _securityKey = GetSecurityKey();
        }

        private static SymmetricSecurityKey GetSecurityKey()
        {
            var secret = GenerateSecret();
            var secretKey = Convert.FromBase64String(secret);
            var securityKey = new SymmetricSecurityKey(secretKey);

            return securityKey;
        }

        private static string GenerateSecret()
        {
            HMACSHA256 hmac = new HMACSHA256();
            string key = Convert.ToBase64String(hmac.Key);
            return key;
        }

        public static string GenerateToken(string username, int expiresMinutes=1)
        {
            
            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] {
                      new Claim(ClaimTypes.Name, username)}),
                Expires = DateTime.UtcNow.AddMinutes(expiresMinutes),
                SigningCredentials = new SigningCredentials(_securityKey,
                SecurityAlgorithms.HmacSha256Signature),
            };
            
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = handler.CreateJwtSecurityToken(descriptor);
            
            token.Payload["k1"] = K1;

            return handler.WriteToken(token);
        }

        public static ClaimsPrincipal GetPrincipal(string token)
        {
            try
            {
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);
                if (jwtToken == null)
                    return null;
                
                TokenValidationParameters parameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = _securityKey
                };

                SecurityToken securityToken;
                ClaimsPrincipal principal = tokenHandler.ValidateToken(token,
                      parameters, out securityToken);

                if (securityToken.ValidTo < DateTime.UtcNow) throw new Exception("token expired");
                if (securityToken.ValidFrom > DateTime.UtcNow) throw new Exception("token not valid expired");

                if (((string)((JwtSecurityToken)securityToken).Payload["k1"]) != K1)
                {
                    throw new Exception("invalid k1");
                }

                return principal;
            }
            catch (Exception e)
            {
                throw;
            }
        }

        public static string ValidateToken(string token)
        {
            string username = null;
            ClaimsPrincipal principal = GetPrincipal(token);
            if (principal == null)
                return null;
            ClaimsIdentity identity = null;
            try
            {
                identity = (ClaimsIdentity)principal.Identity;
            }
            catch (NullReferenceException)
            {
                return null;
            }
            Claim usernameClaim = identity.FindFirst(ClaimTypes.Name);
            username = usernameClaim.Value;
            return username;
        }
    }
}