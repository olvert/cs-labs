<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="login.aspx.cs" Inherits="myWebApplication.login" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>All things Sonic Death Monkey</title>
    <link href="Styles/Site.css" rel="stylesheet" type="text/css" />
</head>
<body>
    <div class="center">
    
    
    <div class="top">
    <form id="form1" runat="server">
    <div>
    <br /><br />
    <asp:Label ID="lblusername" runat="server" Text="Username"></asp:Label>&nbsp;
    <asp:TextBox ID="txtusername" runat="server"></asp:TextBox>&nbsp;&nbsp;
    <asp:Label ID="lblpassword" runat="server" Text="Password"></asp:Label>&nbsp;
    <asp:TextBox ID="txtpassword" runat="server"></asp:TextBox>&nbsp;&nbsp;
    <asp:Button ID="submit" runat="server" Text="Login" onclick="submit_Click" />&nbsp;&nbsp;&nbsp;&nbsp;
    </div>
    </form>
    </div>
    <div class="main">
        <div class="left">
        Everything Sonic Death Monkey. Enter the site. Members only, just like porn, only not really... or is it... 
        <br />
        Go figure it out for yourself. I double-dare you!
        <br />
        <br />
        Page lacks content? YOU lack content.
        </div>
        <div class="right">
            <img src="../images/sdm_jackblack.jpg" height="160px" width="290px" alt="Jb" />
        </div>
    </div>
    <div class="bottom">
        All things Sonic Death Monkey. Directly stolen from High Fidelity movie. As a tribute of sorts... Like it? 
        <a href="Feedback.aspx">Send Feedback</a>&nbsp;&nbsp;
    </div>
    </div>
</body>
</html>
