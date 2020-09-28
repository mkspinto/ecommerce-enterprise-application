using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace MksStoreEnterprise.Identity.API.Models
{
    public class UserViewModels
    {
        //Para dados recebidos através de uma view.

        public class UserRegistry
        {
            [Required(ErrorMessage = "O campo {0} é obrigatório")]
            [EmailAddress(ErrorMessage = "O campo {0} está em formato inválido")]
            public string email { get; set; }

            [Required(ErrorMessage = "O campo {0} é obrigatório")]
            [StringLength(100, ErrorMessage = "O campo {0} precisa ter entre {2} e {1} caracteres", MinimumLength = 6)]
            public string password { get; set; }

            [Compare("password", ErrorMessage = "As senhas não conferem")]
            public string passwordConfirmation { get; set; }
        }

        public class UserLogin
        {
            [Required(ErrorMessage = "O campo {0} é obrigatório")]
            [EmailAddress(ErrorMessage = "O campo {0} está em formato inválido")]
            public string email { get; set; }

            [Required(ErrorMessage = "O campo {0} é obrigatório")]
            [StringLength(100, ErrorMessage = "O campo {0} precisa ter entre {2} e {1} caracteres", MinimumLength = 6)]
            public string password { get; set; }
        }

        public class UserResponseLogin
        {
            public string AccessToken { get; set; }
            public double ExpiresIn { get; set; }
            public UserToken UserToken { get; set; }
        }

        public class UserToken
        {
            public string Id { get; set; }
            public string Email { get; set; }
            public IEnumerable<UserClaim> Claims { get; set; }
        }

        public class UserClaim
        {
            public string Value { get; set; }
            public string Type { get; set; }
        }
    }
}
