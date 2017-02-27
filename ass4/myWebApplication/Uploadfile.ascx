<%@ Control Language="C#" AutoEventWireup="true" CodeBehind="Uploadfile.ascx.cs" Inherits="myWebApplication.Uploadfile" %>

<asp:Label ID="lblStatus" Text="" runat="server" ForeColor="Red" ></asp:Label>
<br />
<asp:Label ID="lblUpload" runat="server" Text="Upload. File. Now!"></asp:Label>
<br />
<asp:FileUpload ID="FileUpload" runat="server" />
<br />
<asp:Button ID="btnUpload" runat="server" Text="Upload" 
    onclick="btnUpload_Click" />

<br />
<br />

<asp:Button ID="btnBack" runat="server" Text="Return" onclick="btnBack_Click" />