import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AnalysisResult } from './models';

@Injectable({ providedIn: 'root' })
export class PasswordService {
  private http   = inject(HttpClient);
  private apiUrl = 'http://localhost:8000';

  analyze(password: string): Observable<AnalysisResult> {
    return this.http.post<AnalysisResult>(`${this.apiUrl}/analyze`, { password });
  }
}