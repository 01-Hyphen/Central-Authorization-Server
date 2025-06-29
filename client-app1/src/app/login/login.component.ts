// src/app/login/login.component.ts
import { Component } from '@angular/core';
import { AuthService } from '../auth/auth.service';

@Component({
  selector: 'app-login',
  template: `<button (click)="login()">Login with Auth Server</button>`
})
export class LoginComponent {
  constructor(private authService: AuthService) { }

  login() {
    this.authService.loginWithPKCE();
  }
}
