using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace myWebApplication
{
    public partial class _default : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            //check if cookie exists, if not redirect to login.aspx
            //go to user table, retrieve the post where the sessionID matches

            if (Request.Cookies.Get("auth") == null)
            {
                Response.Redirect("Login.aspx");
            }
            String username = SQLaccess.GetUserFromID(Request.Cookies.Get("auth").Value);

            if (username != null)
            {
                Session["loggedin"] = true;
                Session["auth"] = Request.Cookies.Get("auth").Value;
                welcome.Text = "Welcome to the system " + username + ".";
                welcome2.Text = "Your sessionID is: " + Session["auth"].ToString() + ".";
                
            }
            else
            {
                Response.Redirect("login.aspx");
            }

            //panels
            Panel_Buy.Visible = false;
            Panel_Thankyou.Visible = false;
            Panel_Uploadfile.Visible = false;
            Panel_Viewcomments.Visible = false;

            int page;
            int.TryParse(Request.QueryString.Get("page"), out page);

            switch (page)
            {
                case 0: break;
                case 1: if ((Boolean)Session["loggedin"] == true) { Panel_Buy.Visible = true; } break;
                case 2: if ((Boolean)Session["loggedin"] == true) { Panel_Thankyou.Visible = true; } break;
                case 3: if ((Boolean)Session["loggedin"] == true) { Panel_Uploadfile.Visible = true; } break;
                case 4: if ((Boolean)Session["loggedin"] == true) { Panel_Viewcomments.Visible = true; } break;
                default: Response.Redirect("login.aspx"); break;
            }
        }

        protected void logout_Click(object sender, EventArgs e)
        {
            //remove sessionID from database
            String record = SQLaccess.GetRecordFromID(Request.Cookies.Get("auth").Value);
            if (record != null)
            {
                SQLaccess.InsertSessionID(record,"-1");
            }
            Request.Cookies.Clear();
            Response.Cookies["auth"].Expires = DateTime.Now;
            Response.Cookies["name"].Expires = DateTime.Now;
            Session.Clear();
            Response.Redirect("login.aspx");
            
        }
    }
}