using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

using WDDN_V2.Models;
using static WDDN_V2.Controllers.HomeController;

namespace WDDN_V2.Controllers
{
    public class TransactionsController : Controller
    {
        private ApplicationUserManager _userManager;
        public TransactionsController()
        {
           
        }
        public TransactionsController(ApplicationUserManager userManager)
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
        
        private DataBaseEntities db = new DataBaseEntities();
        private UsermanagerDBEntities umdb = new UsermanagerDBEntities();
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
        public ActionResult Requestmoney()
        {
            return View();
        }
        // GET: Transactions
       /* public ActionResult Index()
        {
            return View(db.Transactions.ToList());
        }
        [HttpPost]*/
        public async Task<ActionResult> Index(string searchString)
        {
            var data = from m in db.Transactions
                         select m;
                string ID =(from x in umdb.AspNetUsers where x.FullName.Contains(searchString) select x.Id).FirstOrDefault();
            if (!String.IsNullOrEmpty(searchString))
            {
           
                data = data.Where(s => s.Recipient.Contains(searchString) 
                || s.UserId.Contains(searchString) 
                || s.FromAccount.ToString().Contains(searchString)
                || s.ToAccount.ToString().Contains(searchString)
                || s.Date.ToString().Contains(searchString)
                || s.UserId.Contains(ID)
                );
              
            }
                
            return View(await data.ToListAsync());
        }
        // GET: Transactions/Details/5
        public async Task<ActionResult> Details(string id,string searchString,string start,string end)
        {
            if (id == null)
            {
                ViewBag.id = null;
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
             string ID = (from x in umdb.AspNetUsers where x.FullName.Contains(searchString) select x.Id).FirstOrDefault();
            var transaction = (from x in db.Transactions where x.UserId == id select x);//Initialize
            int CurAcc = (from x in umdb.AspNetUsers where x.Id == id select x.AccountNumber).FirstOrDefault();
            ViewBag.CUACC = CurAcc;
            if (Request.QueryString["lim"] != null)
            {
                ViewBag.Act = 1;
                transaction = (from x in db.Transactions where x.UserId == id || CurAcc == x.ToAccount select x).Take(10);
            }
            else
            {
                    transaction = (from x in db.Transactions where x.UserId == id || CurAcc == x.ToAccount select x);
            }  
            if (transaction == null)
            {
                return HttpNotFound();
            }
            if (!String.IsNullOrEmpty(searchString))
            {

                transaction = transaction.Where(s => s.Recipient.Contains(searchString)
                || s.UserId.Contains(searchString)
                || s.FromAccount.ToString().Contains(searchString)
                || s.ToAccount.ToString().Contains(searchString)
                || s.Date.ToString().Contains(searchString)
                || s.UserId.Contains(ID)
                );

            }
            /*if (!String.IsNullOrEmpty(start) && !String.IsNullOrEmpty(end))
            {
                DateTime sd = Convert.ToDateTime(start);
                DateTime ed = Convert.ToDateTime(end);
                transaction = transaction.Where(d => d.Date >= sd && d.Date <= ed);
            }*/
                ViewBag.id = id;
            return View(await transaction.ToListAsync());
           // return View(transaction);
        }
      
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Requestmoney([Bind(Include ="PhoneNumber,Amount")] RequestmoneyViewModel rm)
        {
            if(rm.Amount <= 0)
            {
                ModelState.AddModelError("", "Enter valid amount");
                return View(rm);
            }
            string id = User.Identity.GetUserId();
            string ph = (from x in umdb.AspNetUsers where x.Id ==id select x.PhoneNumber).FirstOrDefault();
            if (rm.PhoneNumber == ph)
            {
                ModelState.AddModelError("", "😁 We found that it's you,enter another number");
                return View(rm);
            }
            string p;
                try
            {
                p = TempData.Peek("ActiveUId").ToString();
            }
            catch(Exception)
            {
                return View("Error");
            }
            string requestmailid= (from x in umdb.AspNetUsers
                                       where x.PhoneNumber == rm.PhoneNumber
                                       select x.Email).SingleOrDefault();
            if (requestmailid == null)
            {
                ModelState.AddModelError("", "It seems that no Account holder for this number.");

                return View(rm);
            }
            string currentusername= (from x in umdb.AspNetUsers
                                     where x.Id == p
                                     select x.FullName).SingleOrDefault();
            string body = "Hello.\n" + currentusername + " is requesting amount of " + rm.Amount + " Rs.\n"
                +"Go to eBank site and make transaction.Thank You.";
            string subject = "Request money";
            SendMailTo(body, subject, requestmailid);
            
           return RedirectToAction("Index","Home", new { Message = ManageMessageId.RequestSuccess });
        }
        // GET: Transactions/Create
        
        public ActionResult SuccessTx()
        {
            return View();
        }
       
        public ActionResult Create()
        {
            string p;
            try
            {
                p = TempData.Peek("ActiveUId").ToString();
            }
            catch(Exception)
            {
                return View("Error");
            }
            if (p == null)
            {
                return View("Error");
            }
            long acno = (from c in umdb.AspNetUsers

                         where c.Id == p
                         select c.AccountNumber).SingleOrDefault();
            ViewBag.CUserAccNo = acno;

            return View();
        }

        string rname;
        int amt;
        // POST: Transactions/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "Id,UserId,FromAccount,ToAccount,Amount,Date,Recipient")] Transaction transaction)
        {
            if (ModelState.IsValid)
            {
                if (transaction.Amount <= 0)
                {
                    ModelState.AddModelError("", "Enter valid amount");
                    return View(transaction);
                }
                if (transaction.FromAccount == transaction.ToAccount)
                {
                    ModelState.AddModelError("", "It's you,try different account number.");
                    return View(transaction);
                }
                rname = "OK";
                string sendermailid = (from x in umdb.AspNetUsers
                                       where x.AccountNumber == transaction.FromAccount
                                       select x.Email).SingleOrDefault();
                string receivermailid = (from x in umdb.AspNetUsers
                                         where x.AccountNumber == transaction.ToAccount
                                         select x.Email).SingleOrDefault();
                rname= (from x in umdb.AspNetUsers
                               where x.AccountNumber == transaction.ToAccount
                               select x.FullName).SingleOrDefault();
                
               amt= transaction.Amount;
                //TempData.Keep("Amount");
                if (receivermailid == null)
                {
                    ModelState.AddModelError("", "Account holder does not exists.");
                    return View(transaction);
                }
               bool EmailCon= (from x in umdb.AspNetUsers
                               where x.AccountNumber == transaction.ToAccount
                               select x.EmailConfirmed).SingleOrDefault();
                if (EmailCon == false)
                {
                    ModelState.AddModelError("", "Recipient account is not active");
                    return View(transaction);
                }
                int currentbalanceofsender=0;
                int currentbalanceofrecipient=0;
                var Q1= (from c in umdb.AspNetUsers

                         where c.AccountNumber == transaction.FromAccount
                         select c);
                
                foreach(AspNetUser x in Q1)
                {
                    currentbalanceofsender = (int)x.Balance;
                    if (currentbalanceofsender <= 0)
                    {
                        ModelState.AddModelError("", "Insufficient balance in your account");
                        return View(transaction);
                    }
                    x.Balance = currentbalanceofsender - transaction.Amount;
                }
                umdb.SaveChanges();
                var Q2= (from c in umdb.AspNetUsers

                         where c.AccountNumber == transaction.ToAccount
                         select c);
                foreach(AspNetUser y in Q2)
                {
                    currentbalanceofrecipient = (int)y.Balance;
                    y.Balance = currentbalanceofrecipient + transaction.Amount;
                }
                
                umdb.SaveChanges();
                db.Transactions.Add(transaction);
                db.SaveChanges();
                
                var body = "Your account is debited by " + transaction.Amount+"/-"
                    +"Current Balance is :"+ (from c in umdb.AspNetUsers

                                              where c.AccountNumber == transaction.FromAccount
                                              select c.Balance).SingleOrDefault();
                var subject = "Debit";
                var body1 = "Your account is credited by " + transaction.Amount + "/-"
                   + "Current Balance is :" + (from c in umdb.AspNetUsers

                                               where c.AccountNumber == transaction.ToAccount
                                               select c.Balance).SingleOrDefault();
                var subject1 = "Credit";
                SendMailTo(body, subject, sendermailid);
                SendMailTo(body1, subject1, receivermailid);
               
                return RedirectToAction("SuccessTx");
            }

            return View(transaction);
        }

        // GET: Transactions/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Transaction transaction = db.Transactions.Find(id);
            if (transaction == null)
            {
                return HttpNotFound();
            }
            return View(transaction);
        }

        // POST: Transactions/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "Id,UserId,FromAccount,ToAccount,Amount,Date,Recipient")] Transaction transaction)
        {
            if (ModelState.IsValid)
            {
                db.Entry(transaction).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            return View(transaction);
        }

        // GET: Transactions/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Transaction transaction = db.Transactions.Find(id);
            if (transaction == null)
            {
                return HttpNotFound();
            }
            return View(transaction);
        }

        // POST: Transactions/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            Transaction transaction = db.Transactions.Find(id);
            db.Transactions.Remove(transaction);
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
