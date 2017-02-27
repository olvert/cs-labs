using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace myWebApplication
{
    public partial class Feedback : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

            if (!IsPostBack)
            {
                Panel_feedback.Visible = true;
                Panel_return.Visible = false;
            }
        }



        protected void btnReturn_Click(object sender, EventArgs e)
        {
            Response.Redirect("login.aspx");
        }

        protected void btnFeedback_Click(object sender, EventArgs e)
        {
            //get stuff and pass to database
            String name = Server.UrlDecode(txtName.Text);
            String comment = Server.UrlDecode(txtFeedback.Text);

            SQLaccess.InsertComment(name,comment);

            Panel_feedback.Visible = false;
            Panel_return.Visible = true;
        }
    }
}