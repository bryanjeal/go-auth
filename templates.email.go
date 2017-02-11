// Copyright 2017 Bryan Jeal <bryan@jeal.ca>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import "github.com/bryanjeal/go-tmpl"

// NewUserEmail can/should be set by applications using auth.
var NewUserEmail = tmpl.EmailMessage{
	From:      "from@example.com",
	Subject:   "Welcome New User",
	PlainText: "Welcome to our service. Thank you for signing up.",
	TplName:   "auth.NewUserEmail",
}

// PasswordResetEmail can/should be set by applications using auth.
var PasswordResetEmail = tmpl.EmailMessage{
	From:      "from@example.com",
	Subject:   "Password Reset",
	PlainText: "Forgot your password? No problem! To reset your password, visit the following link: https://www.example.com/auth/password-reset/%recipient.token% If you did not request to have your password reset you can safely ignore this email. Rest assured your customer account is safe.",
	TplName:   "auth.PasswordResetEmail",
}

// PasswordResetConfirmEmail can/should be set by applications using auth.
var PasswordResetConfirmEmail = tmpl.EmailMessage{
	From:      "from@example.com",
	Subject:   "Password Reset Confirmation",
	PlainText: "Your account's password was recently changed.",
	TplName:   "auth.PasswordResetConfirmEmail",
}

const passwdResetEmailTmpl = `{{define "title"}}Password Reset{{end}}{{define "content"}}<p style="margin:0;padding:1em 0 0 0;line-height:1.5em;font-family:Helvetica Neue, Helvetica, Arial, sans-serif;font-size:14px;color:#000;"> Hello %recipient.firstname% %recipient.lastname%, <br/> <br/> Forgot your password? No problem! <br/> <br/> To reset your password, click the following link: <br/> <a href="https://www.example.com/auth/password-reset/%recipient.token%">Reset Password</a> <br/> <br/> If you did not request to have your password reset you can safely ignore this email. Rest assured your customer account is safe. <br/> <br/> </p>{{end}}`

const newUserEmailTmpl = `{{define "title"}}Welcome New User{{end}}{{define "content"}}<p style="margin:0;padding:1em 0 0 0;line-height:1.5em;font-family:Helvetica Neue, Helvetica, Arial, sans-serif;font-size:14px;color:#000;"> Hello %recipient.firstname% %recipient.lastname%, <br/> <br/> Welcome to our service. Thank you for signing up.<br/> <br/> </p>{{end}}`

const passwdResetConfirmEmailTmpl = `{{define "title"}}Password Reset Complete{{end}}{{define "content"}}<p style="margin:0;padding:1em 0 0 0;line-height:1.5em;font-family:Helvetica Neue, Helvetica, Arial, sans-serif;font-size:14px;color:#000;"> Hello %recipient.firstname% %recipient.lastname%, <br/> <br/> Your account's password was recently changed. <br/> <br/> </p>{{end}}`

const baseHTMLEmailTemplate = `<!DOCTYPE html><html lang="en"> <head> <meta charset="utf-8"/> <title>{{block "title" .}}Default Title{{end}}</title> <style type="text/css"> /*<![CDATA[*/ /* Prevent Webkit and Windows Mobile platforms from changing default font sizes, while not breaking desktop design. */ body{width: 100% !important; -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; margin:0; padding:0;}/* Reset Styles */ body{margin: 0; padding: 0; font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;}img{border: 0; line-height: 100%; outline: none; text-decoration: none;}table td{border-collapse: collapse;}#backgroundTable{height: 100% !important; margin: 0; padding: 0; width: 100% !important;}.content p{margin:0;padding:1em 0 0 0;line-height:1.5em;font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;font-size:14px;color:#000;}/*]]>*/ </style> </head> <body leftmargin="0" marginwidth="0" topmargin="0" marginheight="0" offset="0" style="background-color: #EEEEEE;"> <center> <table id="backgroundTable" height="100%" width="100%" border="0" cellpadding="0" cellspacing="0" style="background-color: #EEEEEE;"> <tr> <td align="center" valign="top" width="60"> &nbsp; </td><td align="center" valign="top"> <table width="100%" height="60" border="0" cellpadding="0" cellspacing="0"> <tr> <td height="60"> &nbsp; </td></tr></table> <table id="templateContainer" width="640" border="0" cellpadding="0" cellspacing="0"> <tr> <td id="header" align="center" valign="top" style="background-color: #FFFFFF; border-top-right-radius: 10px; border-top-left-radius: 10px;"> <table id="header-outer" border="0" cellpadding="0" cellspacing="0"> <tr> <td width="50" height="50"> &nbsp; </td></tr></table> <table id="header-inner" border="0" cellpadding="0" cellspacing="0" style="background-color: #FFFFFF;"> <tr> <td width="50" height="55"> &nbsp; </td><td width="540" height="55">{{block "logo" .}}<img src="https://www.google.com/logos/doodles/2016/lantern-festival-2016-hk-6238324839677952-hp2x.jpg" height="52" style="height: 52px;"/>{{end}}</td><td width="50" height="55"> &nbsp; </td></tr><tr> <td width="640" height="20" colspan="3"> &nbsp; </td></tr></table> </td></tr><tr> <td align="center" valign="top"> <table id="body" border="0" cellpadding="0" cellspacing="0" style="background-color: #FFFFFF;"> <tr> <td width="50"> &nbsp; </td><td class="content" width="540" valign="top" style="text-align: left;">{{block "content" .}}<p style="margin:0;padding:1em 0 0 0;line-height:1.5em;font-family:Helvetica Neue, Helvetica, Arial, sans-serif;font-size:14px;color:#000;"> Hello %recipient.firstname% %recipient.lastname%, <br/> <br/> This is a test message. <br/> <br/> </p>{{end}}</td><td width="50"> &nbsp; </td></tr></table> </td></tr><tr> <td id="footer" align="center" valign="top" style="background-color: #FFFFFF; border-bottom-right-radius: 10px; border-bottom-left-radius: 10px;"> <table id="footer-inner" border="0" cellpadding="0" cellspacing="0"> <tr> <td width="50" height="50"> &nbsp; </td></tr></table> </td></tr><tr> <td width="50" height="50"> &nbsp; </td></tr></table> </td><td align="center" valign="top" width="60"> &nbsp; </td></tr></table> </center> </body></html>`
