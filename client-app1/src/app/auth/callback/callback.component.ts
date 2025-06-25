// src/app/auth/callback.component.ts
import { Component, OnInit } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Router } from '@angular/router';

@Component({
  selector: 'app-callback',
  template: `<p>Logging in...</p>`
})
export class CallbackComponent implements OnInit {
  constructor(private http: HttpClient, private router: Router) { }

  ngOnInit() {
    const code = new URLSearchParams(window.location.search).get('code');
    console.log(code)
    const verifier = sessionStorage.getItem('pkce_code_verifier');

    if (code && verifier) {
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: 'app1-client',
        redirect_uri: 'http://localhost:4200/callback',
        code_verifier: verifier
      });

      this.http.post('/oauth2/token', body.toString(), {
        headers: new HttpHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }),
        withCredentials: true
      }).subscribe((tokens: any) => {
        sessionStorage.setItem('access_token', tokens.access_token);
        console.log(sessionStorage.getItem('access_token'))
        this.router.navigate(['/dashboard']);
      });
    }
  }
}
