package auth

// HTMLTemplates can/should be set by applications using auth.
// Contains a list of templates used by the auth module.
var HTMLTemplates = map[string]string{
	"auth.Tpl.Login": loginTemplate,
}

const loginTemplate = `
{{define "content"}}
<form class="form-horizontal" method="POST" action={{ .Data.LoginURL }}>
<input type="hidden" name="gorilla.csrf.Token" value="{{ .CsrfToken }}">
<fieldset>

<legend>Sign In</legend>

<div class="form-group">
  <label class="col-md-4 control-label" for="email">Email</label>  
  <div class="col-md-5">
  <input id="email" name="email" type="text" placeholder="your.email@example.com" class="form-control input-md" required="">
    
  </div>
</div>

<div class="form-group">
  <label class="col-md-4 control-label" for="password">Password</label>
  <div class="col-md-5">
    <input id="password" name="password" type="password" placeholder="Your Password" class="form-control input-md" required="">
    
  </div>
</div>

<div class="form-group">
  <label class="col-md-4 control-label" for="btn-submit"></label>
  <div class="col-md-4">
    <button id="btn-submit" name="btn-submit" class="btn btn-primary">Login</button>
  </div>
</div>

</fieldset>
</form>

<h1>Or Create a New Account</h1>
<a href="{{ .Data.RegisterURL }}" class="btn btn-primary btn-lg">Sign Up</a>
{{ end }}
`
