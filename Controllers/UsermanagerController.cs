using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace WDDN_V2.Controllers
{
    public class UsermanagerController : Controller
    {
        private UsermanagerDBEntities db = new UsermanagerDBEntities();

        private DBaseEntities noti = new DBaseEntities();
        private DataBaseEntities dbtx = new DataBaseEntities();
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
        public enum ManageMessageId
        {
            AddPhoneSuccess,
            ChangePasswordSuccess,
            SetTwoFactorSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            RemovePhoneSuccess,
            Error
        }
        public ActionResult ChangeInfo()
        {
            string p;
            try
            {
                p = TempData.Peek("ActiveUId").ToString();
            }
            catch (Exception)
            {
                return View("Error");
            }
            if (p== null)
            {
                return View("Error");
            }
            string name = (from c in db.AspNetUsers

                           where c.Id == p
                           select c.FullName).FirstOrDefault();
            ViewBag.name = name;
            return View();
        }
        [HttpPost]
        public ActionResult ChangeInfo([Bind(Include = "Id,UserId,UserName,Issue")] Notification nt)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    noti.Notifications.Add(nt);
                    noti.SaveChanges();
                    return RedirectToAction("Index", "Home");
                }
                catch (System.Data.Entity.Validation.DbEntityValidationException dbEx)
                {
                    Exception raise = dbEx;
                    foreach (var validationErrors in dbEx.EntityValidationErrors)
                    {
                        foreach (var validationError in validationErrors.ValidationErrors)
                        {
                            string message = string.Format("{0}:{1}",
                                validationErrors.Entry.Entity.ToString(),
                                validationError.ErrorMessage);
                            // raise a new exception nesting  
                            // the current instance as InnerException  
                            raise = new InvalidOperationException(message, raise);
                        }
                    }
                    throw raise;
                }
            }


            return View(nt);
        }

        // GET: AspNetUser
        /* public ActionResult Index()
         {

             return View(db.AspNetUsers.ToList());
         }*/
        public async Task<ActionResult> Index(string searchString)
        {
            var data = from m in db.AspNetUsers
                       select m;

            if (!String.IsNullOrEmpty(searchString))
            {

                data = data.Where(s => s.Id.Contains(searchString)
                || s.AccountType.Contains(searchString)
                || s.AccountNumber.ToString().Contains(searchString)
                || s.FullName.Contains(searchString)
                || s.Date_of_Birth.ToString().Contains(searchString)
                || s.Address.Contains(searchString)
                || s.UserName.Contains(searchString)
                || s.Country.Contains(searchString)
                || s.City.Contains(searchString)
                || s.PhoneNumber.ToString().Contains(searchString)
                || s.Pincode.ToString().Contains(searchString)
                );

            }

            return View(await data.ToListAsync());
        }
        // GET: AspNetUser/Details/5
        public ActionResult Details(string id, ManageMessageId? message)
        {
            ViewBag.StatusMessage =
               message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
               : message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
               : message == ManageMessageId.SetTwoFactorSuccess ? "Your two-factor authentication provider has been set."
               : message == ManageMessageId.Error ? "An error has occurred."
               : message == ManageMessageId.AddPhoneSuccess ? "Your phone number was added."
               : message == ManageMessageId.RemovePhoneSuccess ? "Your phone number was removed."
               : "";
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            AspNetUser aspuser = db.AspNetUsers.Find(id);
            if (aspuser == null)
            {
                return HttpNotFound();
            }
            return View(aspuser);
        }

        // GET: AspNetUser/Edit/5
        public ActionResult Edit(string id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            AspNetUser aspuser = db.AspNetUsers.Find(id);
            if (aspuser == null)
            {
                return HttpNotFound();
            }
            return View(aspuser);
        }
       
        // POST: AspNetUser/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "AccountNumber,Id,FullName,Guardian_Name,PhoneNumber,Email,Date_of_Birth,Address,City,Pincode,State,Country")] AspNetUser aspuser)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    aspuser.UserName = aspuser.Email;
                    db.Entry(aspuser).State = EntityState.Modified;
                    SendMailTo("Your Profile hase been updated.", "Profile update", aspuser.Email);
                    db.SaveChanges();
                    return RedirectToAction("Index");
                }
            }
            catch (System.Data.Entity.Validation.DbEntityValidationException dbEx)  
            {
                Exception raise = dbEx;
                foreach (var validationErrors in dbEx.EntityValidationErrors)
                {
                    foreach (var validationError in validationErrors.ValidationErrors)
                    {
                        string message = string.Format("{0}:{1}",
                            validationErrors.Entry.Entity.ToString(),
                            validationError.ErrorMessage);
                        // raise a new exception nesting  
                        // the current instance as InnerException  
                        raise = new InvalidOperationException(message, raise);
                    }
                }
                throw raise;
            }
            return View(aspuser);

        }

        // GET: AspNetUser/Delete/5
        public ActionResult Delete(string id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            AspNetUser aspuser = db.AspNetUsers.Find(id);
            if (aspuser == null)
            {
                return HttpNotFound();
            }
            return View(aspuser);
        }

        // POST: AspNetUser/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]

        public ActionResult DeleteConfirmed(string id)
        {
            AspNetUser aspuser = db.AspNetUsers.Find(id);
            
            db.AspNetUsers.Remove(aspuser);
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
