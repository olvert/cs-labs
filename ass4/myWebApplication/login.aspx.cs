using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Security.Cryptography;

namespace myWebApplication
{
    public partial class login : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void submit_Click(object sender, EventArgs e)
        {
            String record;
            if ((record = SQLaccess.checkUserPass(txtusername.Text, txtpassword.Text)) == null)
            {
                //no such user, redirect
                Response.Redirect("login.aspx");
            }

            //this is a problem

            else
            {
                //set cookie
                //generate secure random number as session cookie
                byte [] b = new byte[10];
                RandomNumberGenerator rng = RandomNumberGenerator.Create();
                rng.GetBytes(b);
                String sid = Helpers.CalculateMD5Hash(b);
                HttpCookie auth = new HttpCookie("auth",sid);
                //write session cookie to database for user
                SQLaccess.InsertSessionID(record, sid);

                Session["auth"] = auth;
                Response.Cookies.Add(auth);
                Response.Redirect("default.aspx?page=0");
            }
            
        }
    }
}