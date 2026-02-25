import { Directive, ElementRef, Input, OnChanges } from '@angular/core';

/**
 * Direttiva per animare un valore numerico da 0 al valore target.
 * Uso: <span [animCounter]="value" [decimals]="1"></span>
 */
@Directive({ selector: '[animCounter]', standalone: true })
export class AnimCounterDirective implements OnChanges {
  @Input('animCounter') targetValue: number = 0;
  @Input() decimals: number = 0;

  constructor(private el: ElementRef<HTMLElement>) {}

  ngOnChanges(): void {
    const end      = this.targetValue;
    const duration = 550;
    const start    = performance.now();

    const step = (now: number) => {
      const t      = Math.min((now - start) / duration, 1);
      const eased  = 1 - Math.pow(1 - t, 3); // easeOutCubic
      this.el.nativeElement.textContent = (end * eased).toFixed(this.decimals);
      if (t < 1) requestAnimationFrame(step);
    };

    requestAnimationFrame(step);
  }
}