using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using WDDN_V2.Models;
namespace WDDN_V2.Controllers
{
    public class ActiveaccountController : Controller
    {
        private ApplicationUserManager _userManager;
        public ActiveaccountController()
        {
        }

        public ActiveaccountController(ApplicationUserManager userManager)
        {
            UserManager = userManager;
           
        }
        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }
        public void SendMailTo(string body, string subject, string email)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var senderEmail = new MailAddress("bankingsys12@gmail.com", "eBank");
                    var receiverEmail = new MailAddress(email, "Receiver");
                    var password = "ASqw12!@";

                    var smtp = new SmtpClient
                    {
                        Host = "smtp.gmail.com",
                        Port = 587,
                        EnableSsl = true,
                        DeliveryMethod = SmtpDeliveryMethod.Network,
                        UseDefaultCredentials = false,
                        Credentials = new NetworkCredential(senderEmail.Address, password)
                    };
                    using (var mess = new MailMessage(senderEmail, receiverEmail)
                    {
                        Subject = subject,
                        Body = body
                    })
                    {
                        smtp.Send(mess);
                    }

                }
            }
            catch (Exception)
            {
                ViewBag.Error = "Some Error";
            }

        }
        public ActionResult AccountAddSuccess()
        {
            return View();
        }
        public ActionResult ActivateAccount()
        {

            return View();
        }
        public ActionResult SuccessTx()
        {
            return View();
        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ActivateAccount(ActivateAccountViewModel model)
        {

            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "User does not exists");
                return View(model);
            }
            if (!(await UserManager.IsEmailConfirmedAsync(user.Id)))
            {
                var subject = "Account Activation";

                Random r = new Random();
                int otp = 0;
                for (int i = 1; i < 100; i++)
                    otp = r.Next(10000, 99999);

                var body = otp+" is an OTP to activate your account. ";
                TempData["ActivateOTP"] = otp;
                TempData["ActivateEmail"] = model.Email;
                SendMailTo(body, subject, model.Email);
                // Don't reveal that the user does not exist or is not confirmed

                return RedirectToAction("VerifyAccountOTP", "Activeaccount");
            }
            else
            {
                ModelState.AddModelError("", "Your account is already active");
                return View(model);
            }
            

        }
        public ActionResult VerifyAccountOTP()
        {
            return View();
        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyAccountOTP(VerifyAccountOTPViewModel model)
        {

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (Convert.ToInt32(TempData["ActivateOTP"]) == model.OTP)
            {
                var user = await UserManager.FindByNameAsync(TempData["ActivateEmail"].ToString());
                string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);

                if (user.Id == null || code == null)
                {
                    return View("Error");
                }

                var result = await UserManager.ConfirmEmailAsync(user.Id, code);
                var subject = "Account Activated";
                var body = "Your account has been activated successfully.";
                SendMailTo(body, subject, TempData["ActivateEmail"].ToString());
                return View(result.Succeeded ? "ConfirmEmail" : "Error");
            }
            else
            {
                ModelState.AddModelError("", "Invalid OTP");
                return View(model);
            }
           
        }

       

      
      
    }
}