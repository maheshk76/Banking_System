using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace WDDN_V2.Models
{
    public class DetailsViewModel
    {
        [Display(Name = "Search")]
        public string Search { get; set; }
    }
   public class LockAccountViewModel
    {
        [Required]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
    public class LockAccountOTPViewModel
    {
        [Required]
        [Display(Name = "OTP")]
        public int OTP { get; set; }
    }
    public class RequestmoneyViewModel
    {
        [Required]
        [Phone]
        [RegularExpression(@"^([0-9]{10})$", ErrorMessage = "Mobile number should be of 10 digits only")]
        [Display(Name = "PhoneNumber")]
        public string PhoneNumber { get; set; }
        [Required]
        [Display(Name = "Amount")]
        public int Amount { get; set; }
    }
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
  
    public class VerifyAccountOTPViewModel
    {
        [Required]
        [Display(Name = "OTP")]
        public int OTP { get; set; }
        public string Code { get; set; }
    }
    public class ActivateAccountViewModel
    {
        [Required]
        [Display(Name = "Email")]
        public string Email { get; set; }

    }
    public class TransferViewModel
    {
        [Required]
        [Display(Name ="Account_Number")]
        public int Account_Number { get; set; }
        [Required]
        [Display(Name = "Confirm_Account_Number")]
        public int Confirm_Account_Number { get; set; }
        [Required]
        [Display(Name = "IFSC_Code")]
        public int IFSC_Code { get; set; }
        [Required]
        [Display(Name = "Recipient_Name")]
        public int Recipient_Name { get; set; }
    }
    public class ExternalLoginListViewModel
    {
        public string ReturnUrl { get; set; }
    }

    public class SendCodeViewModel
    {
        public string SelectedProvider { get; set; }
        public ICollection<System.Web.Mvc.SelectListItem> Providers { get; set; }
        public string ReturnUrl { get; set; }
        public bool RememberMe { get; set; }
    }

    public class VerifyCodeViewModel
    {
        [Required]
        public string Provider { get; set; }

        [Required]
        [Display(Name = "Code")]
        public string Code { get; set; }
        public string ReturnUrl { get; set; }

        [Display(Name = "Remember this browser?")]
        public bool RememberBrowser { get; set; }

        public bool RememberMe { get; set; }
    }

    public class ForgotViewModel
    {
        [Required]
        [Display(Name = "Email")]
        public string Email { get; set; }
        [Required]
        [Display(Name = "OTP")]
        public string OTP { get; set; }
      
    }

    public class LoginViewModel
    {
        [Required]
        [Display(Name = "Email")]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }

    public class RegisterViewModel
    {
        [Required]
        [Display(Name = "AccountType")]
        public string AccountType { get; set; }
        [Required]
        [Display(Name = "AccountNumber")]
        public int AccountNumber { get; set; }
        [Required]
        [Display(Name ="FullName")]
        public string Name { get; set; }
        [Required]
        [Display(Name = "Guardian's Name")]
        public string Guardian_Name { get; set; }
        [Required]
       
        [Display(Name = "Date of birth")]
        [DataType(DataType.Date)]

        [DisplayFormat(ApplyFormatInEditMode = true, DataFormatString = "{0:yyyy-MM-dd}")]
        public string Date_of_birth { get; set; }
        [Required]
        [Phone]
        [Display(Name = "Mobile_Number")]
        [RegularExpression(@"^([0-9]{10})$",ErrorMessage ="Mobile Number should be of 10 digits only")]
        public string Mobile_Number { get; set; }
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }
        [Required]
        
        [Display(Name = "Address")]
        [MaxLength(100)]
        public string Address { get; set; }
        [Required]
        [Display(Name = "City")]
        public string City { get; set; }
        [Required]
        [Display(Name = "State")]
        public string State { get; set; }
        [Required]
        [Display(Name = "Pincode")]
        [RegularExpression(@"^([0-9]{6})$",ErrorMessage ="Invalid Pincode ")]
        public string Pincode { get; set; }
        [Required]
        [Display(Name = "Country")]
        public string Country { get; set; }
        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
        
        [Display(Name = "Aadhaar proof")]
        public string Aadhaar_Proof { get; set; }
        [Display(Name = "Address proof")]
        public string Address_Proof { get; set; }

    }

    public class ResetPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        public string Code { get; set; }
    }

    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
    public class ForgotPasswordConfirmationViewModel
    {
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "New_Password")]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        public string New_Password { get; set; }
        [DataType(DataType.Password)]
        [Display(Name = "Confirm_Password")]
        [Compare("New_Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string Confirm_Password { get; set; }

        [Required]
        [Display(Name = "OTP")]

        public int OTP { get; set; }
        public string Code { get; set; }
 
    }
   

}
