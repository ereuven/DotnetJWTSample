using System.Collections.Generic;
using System.Linq;

namespace AuthenticationJWT
{
    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }

    }

    public enum UserRole
    {
        NORMAL,
        ADMIN
    }

    public class UserRepository
    {
        public List<User> TestUsers;
        public UserRepository()
        {
            TestUsers = new List<User>();
            TestUsers.Add(new User() { Username = "Test1", Password = "Pass1" });
            TestUsers.Add(new User() { Username = "Test2", Password = "Pass2" });
        }
        public User GetUser(string username)
        {
            try
            {
                return TestUsers.First(user => user.Username.Equals(username));
            }
            catch
            {
                return null;
            }
        }
    }
}