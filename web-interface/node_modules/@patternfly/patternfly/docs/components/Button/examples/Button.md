---
id: Button
section: components
cssPrefix: pf-v6-c-button
---import './Button.css'

## Examples

### Variations

```html
<button class="pf-v6-c-button pf-m-primary" type="button">
  <span class="pf-v6-c-button__text">Primary</span>
</button>

<button class="pf-v6-c-button pf-m-secondary" type="button">
  <span class="pf-v6-c-button__text">Secondary</span>
</button>

<button class="pf-v6-c-button pf-m-danger pf-m-secondary" type="button">
  <span class="pf-v6-c-button__text">Secondary danger</span>
</button>

<button class="pf-v6-c-button pf-m-tertiary" type="button">
  <span class="pf-v6-c-button__text">Tertiary</span>
</button>

<button class="pf-v6-c-button pf-m-danger" type="button">
  <span class="pf-v6-c-button__text">Danger</span>
</button>

<button class="pf-v6-c-button pf-m-warning" type="button">
  <span class="pf-v6-c-button__text">Warning</span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Link</span>
</button>

<button class="pf-v6-c-button pf-m-link pf-m-danger" type="button">
  <span class="pf-v6-c-button__text">Link danger</span>
</button>

<button class="pf-v6-c-button pf-m-inline pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Inline link</span>
</button>

<button class="pf-v6-c-button pf-m-plain" type="button" aria-label="Remove">
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-control" type="button">
  <span class="pf-v6-c-button__text">Control</span>
</button>

<button
  class="pf-v6-c-button pf-m-control"
  type="button"
  aria-label="Copy input"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<div>
  <strong>Icon</strong>
</div>
<button class="pf-v6-c-button pf-m-primary" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Primary</span>
</button>

<button class="pf-v6-c-button pf-m-secondary" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Secondary</span>
</button>

<button class="pf-v6-c-button pf-m-danger pf-m-secondary" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Secondary danger</span>
</button>

<button class="pf-v6-c-button pf-m-tertiary" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Tertiary</span>
</button>

<button class="pf-v6-c-button pf-m-danger" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Danger</span>
</button>

<button class="pf-v6-c-button pf-m-warning" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Warning</span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-link" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Link</span>
</button>

<button class="pf-v6-c-button pf-m-link pf-m-danger" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Link danger</span>
</button>

<button class="pf-v6-c-button pf-m-inline pf-m-link" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Inline link</span>
</button>

<button class="pf-v6-c-button pf-m-plain" type="button" aria-label="Remove">
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-control" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Control</span>
</button>

<button
  class="pf-v6-c-button pf-m-control"
  type="button"
  aria-label="Copy input"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<div>
  <strong>Icon end</strong>
</div>
<button class="pf-v6-c-button pf-m-primary" type="button">
  <span class="pf-v6-c-button__text">Primary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-secondary" type="button">
  <span class="pf-v6-c-button__text">Secondary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-danger pf-m-secondary" type="button">
  <span class="pf-v6-c-button__text">Secondary danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-tertiary" type="button">
  <span class="pf-v6-c-button__text">Tertiary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-danger" type="button">
  <span class="pf-v6-c-button__text">Danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-warning" type="button">
  <span class="pf-v6-c-button__text">Warning</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Link</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-link pf-m-danger" type="button">
  <span class="pf-v6-c-button__text">Link danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-inline pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Inline link</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-plain" type="button" aria-label="Remove">
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-control" type="button">
  <span class="pf-v6-c-button__text">Control</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-control"
  type="button"
  aria-label="Copy input"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

```

### Clicked buttons

```html
<button class="pf-v6-c-button pf-m-clicked pf-m-primary" type="button">
  <span class="pf-v6-c-button__text">Primary</span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-secondary" type="button">
  <span class="pf-v6-c-button__text">Secondary</span>
</button>

<button
  class="pf-v6-c-button pf-m-clicked pf-m-danger pf-m-secondary"
  type="button"
>
  <span class="pf-v6-c-button__text">Secondary danger</span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-tertiary" type="button">
  <span class="pf-v6-c-button__text">Tertiary</span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-danger" type="button">
  <span class="pf-v6-c-button__text">Danger</span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-warning" type="button">
  <span class="pf-v6-c-button__text">Warning</span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-clicked pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Link</span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-link pf-m-danger" type="button">
  <span class="pf-v6-c-button__text">Link danger</span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-inline pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Inline link</span>
</button>

<button
  class="pf-v6-c-button pf-m-clicked pf-m-plain"
  type="button"
  aria-label="Remove"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-clicked pf-m-control" type="button">
  <span class="pf-v6-c-button__text">Control</span>
</button>

<button
  class="pf-v6-c-button pf-m-clicked pf-m-control"
  type="button"
  aria-label="Copy input"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<div>
  <strong>Icon</strong>
</div>
<button class="pf-v6-c-button pf-m-clicked pf-m-primary" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Primary</span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-secondary" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Secondary</span>
</button>

<button
  class="pf-v6-c-button pf-m-clicked pf-m-danger pf-m-secondary"
  type="button"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Secondary danger</span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-tertiary" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Tertiary</span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-danger" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Danger</span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-warning" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Warning</span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-clicked pf-m-link" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Link</span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-link pf-m-danger" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Link danger</span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-inline pf-m-link" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Inline link</span>
</button>

<button
  class="pf-v6-c-button pf-m-clicked pf-m-plain"
  type="button"
  aria-label="Remove"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-clicked pf-m-control" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Control</span>
</button>

<button
  class="pf-v6-c-button pf-m-clicked pf-m-control"
  type="button"
  aria-label="Copy input"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<div>
  <strong>Icon end</strong>
</div>
<button class="pf-v6-c-button pf-m-clicked pf-m-primary" type="button">
  <span class="pf-v6-c-button__text">Primary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-secondary" type="button">
  <span class="pf-v6-c-button__text">Secondary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-clicked pf-m-danger pf-m-secondary"
  type="button"
>
  <span class="pf-v6-c-button__text">Secondary danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-tertiary" type="button">
  <span class="pf-v6-c-button__text">Tertiary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-danger" type="button">
  <span class="pf-v6-c-button__text">Danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-warning" type="button">
  <span class="pf-v6-c-button__text">Warning</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-clicked pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Link</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-link pf-m-danger" type="button">
  <span class="pf-v6-c-button__text">Link danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-clicked pf-m-inline pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Inline link</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-clicked pf-m-plain"
  type="button"
  aria-label="Remove"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-clicked pf-m-control" type="button">
  <span class="pf-v6-c-button__text">Control</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-clicked pf-m-control"
  type="button"
  aria-label="Copy input"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

```

### Small buttons

```html
<button class="pf-v6-c-button pf-m-small pf-m-primary" type="button">
  <span class="pf-v6-c-button__text">Primary</span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-secondary" type="button">
  <span class="pf-v6-c-button__text">Secondary</span>
</button>

<button
  class="pf-v6-c-button pf-m-small pf-m-danger pf-m-secondary"
  type="button"
>
  <span class="pf-v6-c-button__text">Secondary danger</span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-tertiary" type="button">
  <span class="pf-v6-c-button__text">Tertiary</span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-danger" type="button">
  <span class="pf-v6-c-button__text">Danger</span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-warning" type="button">
  <span class="pf-v6-c-button__text">Warning</span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-small pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Link</span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-link pf-m-danger" type="button">
  <span class="pf-v6-c-button__text">Link danger</span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-inline pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Inline link</span>
</button>

<button
  class="pf-v6-c-button pf-m-small pf-m-plain"
  type="button"
  aria-label="Remove"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-small pf-m-control" type="button">
  <span class="pf-v6-c-button__text">Control</span>
</button>

<button
  class="pf-v6-c-button pf-m-small pf-m-control"
  type="button"
  aria-label="Copy input"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<div>
  <strong>Icon</strong>
</div>
<button class="pf-v6-c-button pf-m-small pf-m-primary" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Primary</span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-secondary" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Secondary</span>
</button>

<button
  class="pf-v6-c-button pf-m-small pf-m-danger pf-m-secondary"
  type="button"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Secondary danger</span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-tertiary" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Tertiary</span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-danger" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Danger</span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-warning" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Warning</span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-small pf-m-link" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Link</span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-link pf-m-danger" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Link danger</span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-inline pf-m-link" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Inline link</span>
</button>

<button
  class="pf-v6-c-button pf-m-small pf-m-plain"
  type="button"
  aria-label="Remove"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-small pf-m-control" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Control</span>
</button>

<button
  class="pf-v6-c-button pf-m-small pf-m-control"
  type="button"
  aria-label="Copy input"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<div>
  <strong>Icon end</strong>
</div>
<button class="pf-v6-c-button pf-m-small pf-m-primary" type="button">
  <span class="pf-v6-c-button__text">Primary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-secondary" type="button">
  <span class="pf-v6-c-button__text">Secondary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-small pf-m-danger pf-m-secondary"
  type="button"
>
  <span class="pf-v6-c-button__text">Secondary danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-tertiary" type="button">
  <span class="pf-v6-c-button__text">Tertiary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-danger" type="button">
  <span class="pf-v6-c-button__text">Danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-warning" type="button">
  <span class="pf-v6-c-button__text">Warning</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-small pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Link</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-link pf-m-danger" type="button">
  <span class="pf-v6-c-button__text">Link danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-small pf-m-inline pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Inline link</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-small pf-m-plain"
  type="button"
  aria-label="Remove"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-small pf-m-control" type="button">
  <span class="pf-v6-c-button__text">Control</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-small pf-m-control"
  type="button"
  aria-label="Copy input"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

```

### Disabled

```html
<button class="pf-v6-c-button pf-m-primary" type="button" disabled>
  <span class="pf-v6-c-button__text">Primary</span>
</button>

<button class="pf-v6-c-button pf-m-secondary" type="button" disabled>
  <span class="pf-v6-c-button__text">Secondary</span>
</button>

<button
  class="pf-v6-c-button pf-m-danger pf-m-secondary"
  type="button"
  disabled
>
  <span class="pf-v6-c-button__text">Secondary danger</span>
</button>

<button class="pf-v6-c-button pf-m-tertiary" type="button" disabled>
  <span class="pf-v6-c-button__text">Tertiary</span>
</button>

<button class="pf-v6-c-button pf-m-danger" type="button" disabled>
  <span class="pf-v6-c-button__text">Danger</span>
</button>

<button class="pf-v6-c-button pf-m-warning" type="button" disabled>
  <span class="pf-v6-c-button__text">Warning</span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-link" type="button" disabled>
  <span class="pf-v6-c-button__text">Link</span>
</button>

<button class="pf-v6-c-button pf-m-link pf-m-danger" type="button" disabled>
  <span class="pf-v6-c-button__text">Link danger</span>
</button>

<button class="pf-v6-c-button pf-m-inline pf-m-link" type="button" disabled>
  <span class="pf-v6-c-button__text">Inline link</span>
</button>

<button
  class="pf-v6-c-button pf-m-plain"
  type="button"
  aria-label="Remove"
  disabled
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-control" type="button" disabled>
  <span class="pf-v6-c-button__text">Control</span>
</button>

<button
  class="pf-v6-c-button pf-m-control"
  type="button"
  aria-label="Copy input"
  disabled
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<div>
  <strong>Icon</strong>
</div>
<button class="pf-v6-c-button pf-m-primary" type="button" disabled>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Primary</span>
</button>

<button class="pf-v6-c-button pf-m-secondary" type="button" disabled>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Secondary</span>
</button>

<button
  class="pf-v6-c-button pf-m-danger pf-m-secondary"
  type="button"
  disabled
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Secondary danger</span>
</button>

<button class="pf-v6-c-button pf-m-tertiary" type="button" disabled>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Tertiary</span>
</button>

<button class="pf-v6-c-button pf-m-danger" type="button" disabled>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Danger</span>
</button>

<button class="pf-v6-c-button pf-m-warning" type="button" disabled>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Warning</span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-link" type="button" disabled>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Link</span>
</button>

<button class="pf-v6-c-button pf-m-link pf-m-danger" type="button" disabled>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Link danger</span>
</button>

<button class="pf-v6-c-button pf-m-inline pf-m-link" type="button" disabled>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Inline link</span>
</button>

<button
  class="pf-v6-c-button pf-m-plain"
  type="button"
  aria-label="Remove"
  disabled
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-control" type="button" disabled>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Control</span>
</button>

<button
  class="pf-v6-c-button pf-m-control"
  type="button"
  aria-label="Copy input"
  disabled
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<div>
  <strong>Icon end</strong>
</div>
<button class="pf-v6-c-button pf-m-primary" type="button" disabled>
  <span class="pf-v6-c-button__text">Primary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-secondary" type="button" disabled>
  <span class="pf-v6-c-button__text">Secondary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-danger pf-m-secondary"
  type="button"
  disabled
>
  <span class="pf-v6-c-button__text">Secondary danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-tertiary" type="button" disabled>
  <span class="pf-v6-c-button__text">Tertiary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-danger" type="button" disabled>
  <span class="pf-v6-c-button__text">Danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-warning" type="button" disabled>
  <span class="pf-v6-c-button__text">Warning</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-link" type="button" disabled>
  <span class="pf-v6-c-button__text">Link</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-link pf-m-danger" type="button" disabled>
  <span class="pf-v6-c-button__text">Link danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-inline pf-m-link" type="button" disabled>
  <span class="pf-v6-c-button__text">Inline link</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-plain"
  type="button"
  aria-label="Remove"
  disabled
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button class="pf-v6-c-button pf-m-control" type="button" disabled>
  <span class="pf-v6-c-button__text">Control</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-control"
  type="button"
  aria-label="Copy input"
  disabled
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

```

### Aria-disabled

```html
<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-primary"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Primary</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-secondary"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Secondary</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-danger pf-m-secondary"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Secondary danger</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-tertiary"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Tertiary</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-danger"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Danger</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-warning"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Warning</span>
</button>

<br />
<br />

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-link"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Link</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-link pf-m-danger"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Link danger</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-inline pf-m-link"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Inline link</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-plain"
  type="button"
  aria-label="Remove"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-control"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Control</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-control"
  type="button"
  aria-label="Copy input"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<div>
  <strong>Icon</strong>
</div>
<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-primary"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Primary</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-secondary"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Secondary</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-danger pf-m-secondary"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Secondary danger</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-tertiary"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Tertiary</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-danger"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Danger</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-warning"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Warning</span>
</button>

<br />
<br />

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-link"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Link</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-link pf-m-danger"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Link danger</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-inline pf-m-link"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Inline link</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-plain"
  type="button"
  aria-label="Remove"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-control"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">Control</span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-control"
  type="button"
  aria-label="Copy input"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<div>
  <strong>Icon end</strong>
</div>
<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-primary"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Primary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-secondary"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Secondary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-danger pf-m-secondary"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Secondary danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-tertiary"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Tertiary</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-danger"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-warning"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Warning</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-link"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Link</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-link pf-m-danger"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Link danger</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-inline pf-m-link"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Inline link</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-plain"
  type="button"
  aria-label="Remove"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</button>

<br />
<br />

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-control"
  type="button"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__text">Control</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-plus-circle" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-aria-disabled pf-m-control"
  type="button"
  aria-label="Copy input"
  aria-disabled="true"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </span>
</button>

```

### Links as buttons

```html
<a
  class="pf-v6-c-button pf-m-primary"
  href="https://www.w3.org/TR/WCAG20-TECHS/ARIA8.html#ARIA8-examples"
>
  <span class="pf-v6-c-button__text">Primary link to W3.org</span>
</a>

<a
  class="pf-v6-c-button pf-m-secondary"
  aria-label="Read more about button documentation"
  href="#overview"
>
  <span class="pf-v6-c-button__text">Secondary link to anchor</span>
</a>

<a
  class="pf-v6-c-button pf-m-danger pf-m-secondary"
  aria-label="Read more about button documentation"
  href="#overview"
>
  <span class="pf-v6-c-button__text">Secondary danger link to anchor</span>
</a>

<a
  class="pf-v6-c-button pf-m-tertiary pf-m-disabled"
  href="https://www.w3.org/TR/WCAG20-TECHS/ARIA8.html#ARIA8-examples"
  aria-disabled="true"
  tabindex="-1"
>
  <span class="pf-v6-c-button__text">Tertiary link to W3.org</span>
</a>

<a
  class="pf-v6-c-button pf-m-link"
  href="https://www.w3.org/TR/WCAG20-TECHS/ARIA8.html#ARIA8-examples"
>
  <span class="pf-v6-c-button__text">Link to W3.org</span>
</a>

<a
  class="pf-v6-c-button pf-m-link pf-m-danger"
  href="https://www.w3.org/TR/WCAG20-TECHS/ARIA8.html#ARIA8-examples"
>
  <span class="pf-v6-c-button__text">Link danger to W3.org</span>
</a>

```

### Inline link as span

```html
<strong>Plain</strong>
<br />
<span
  class="pf-v6-c-button pf-m-plain"
  type="button"
  role="button"
  tabindex="0"
  aria-label="Remove"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</span>
<br />
<br />
<strong>Plain no padding</strong>
<br />
<span
  class="pf-v6-c-button pf-m-no-padding pf-m-plain"
  type="button"
  role="button"
  tabindex="0"
  aria-label="Remove"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-times" aria-hidden="true"></i>
  </span>
</span>
<br />
<br />
<strong>Inline link</strong>
<br />Lorem ipsum dolor sit amet, consectetur adipiscing elit.
<span
  class="pf-v6-c-button pf-m-inline pf-m-link"
  type="button"
  role="button"
  tabindex="0"
>
  <span
    class="pf-v6-c-button__text"
  >This is long button text that needs to be a span so that it will wrap inline with the text around it.</span>
</span>
Sed hendrerit nisi in cursus maximus. Ut malesuada nisi turpis, in condimentum velit elementum non.

```

### Block level

```html
<button class="pf-v6-c-button pf-m-block pf-m-primary" type="button">
  <span class="pf-v6-c-button__text">Block level button</span>
</button>

```

### Types

```html
<button class="pf-v6-c-button pf-m-primary" type="submit">
  <span class="pf-v6-c-button__text">Submit</span>
</button>

<button class="pf-v6-c-button pf-m-primary" type="reset">
  <span class="pf-v6-c-button__text">Reset</span>
</button>

<button class="pf-v6-c-button pf-m-primary" type="button">
  <span class="pf-v6-c-button__text">Default</span>
</button>

```

### Call to action

```html
<button class="pf-v6-c-button pf-m-display-lg pf-m-primary" type="button">
  <span class="pf-v6-c-button__text">Call to action</span>
</button>

<button class="pf-v6-c-button pf-m-display-lg pf-m-secondary" type="button">
  <span class="pf-v6-c-button__text">Call to action</span>
</button>

<button class="pf-v6-c-button pf-m-display-lg pf-m-tertiary" type="button">
  <span class="pf-v6-c-button__text">Call to action</span>
</button>

<button class="pf-v6-c-button pf-m-display-lg pf-m-link" type="button">
  <span class="pf-v6-c-button__text">Call to action</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-arrow-right" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-display-lg pf-m-inline pf-m-link"
  type="button"
>
  <span class="pf-v6-c-button__text">Call to action</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-arrow-right" aria-hidden="true"></i>
  </span>
</button>
<br />
<br />
<strong>disabled</strong>
<br />
<button
  class="pf-v6-c-button pf-m-display-lg pf-m-primary"
  type="button"
  disabled
>
  <span class="pf-v6-c-button__text">Call to action</span>
</button>

<button
  class="pf-v6-c-button pf-m-display-lg pf-m-secondary"
  type="button"
  disabled
>
  <span class="pf-v6-c-button__text">Call to action</span>
</button>

<button
  class="pf-v6-c-button pf-m-display-lg pf-m-tertiary"
  type="button"
  disabled
>
  <span class="pf-v6-c-button__text">Call to action</span>
</button>

<button class="pf-v6-c-button pf-m-display-lg pf-m-link" type="button" disabled>
  <span class="pf-v6-c-button__text">Call to action</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-arrow-right" aria-hidden="true"></i>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-display-lg pf-m-inline pf-m-link"
  type="button"
  disabled
>
  <span class="pf-v6-c-button__text">Call to action</span>
  <span class="pf-v6-c-button__icon pf-m-end">
    <i class="fas fa-arrow-right" aria-hidden="true"></i>
  </span>
</button>

```

### Progress

```html
<button class="pf-v6-c-button pf-m-progress pf-m-primary" type="button">
  <span class="pf-v6-c-button__text">Primary loader</span>
</button>

<button
  class="pf-v6-c-button pf-m-in-progress pf-m-progress pf-m-primary"
  type="button"
>
  <span class="pf-v6-c-button__progress">
    <svg
      class="pf-v6-c-spinner pf-m-md"
      role="progressbar"
      viewBox="0 0 100 100"
      aria-label="Loading..."
    >
      <circle class="pf-v6-c-spinner__path" cx="50" cy="50" r="45" fill="none" />
    </svg>
  </span>

  <span class="pf-v6-c-button__text">Primary loading</span>
</button>
<br />
<button class="pf-v6-c-button pf-m-progress pf-m-secondary" type="button">
  <span class="pf-v6-c-button__text">Secondary loader</span>
</button>

<button
  class="pf-v6-c-button pf-m-in-progress pf-m-progress pf-m-secondary"
  type="button"
>
  <span class="pf-v6-c-button__progress">
    <svg
      class="pf-v6-c-spinner pf-m-md"
      role="progressbar"
      viewBox="0 0 100 100"
      aria-label="Loading..."
    >
      <circle class="pf-v6-c-spinner__path" cx="50" cy="50" r="45" fill="none" />
    </svg>
  </span>

  <span class="pf-v6-c-button__text">Secondary loading</span>
</button>
<br />
<button class="pf-v6-c-button pf-m-plain" type="button" aria-label="Upload">
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-upload" aria-hidden="true"></i>
  </span>
</button>

<button class="pf-v6-c-button pf-m-in-progress pf-m-plain" type="button">
  <span class="pf-v6-c-button__progress">
    <svg
      class="pf-v6-c-spinner pf-m-md"
      role="progressbar"
      viewBox="0 0 100 100"
      aria-label="Uploading..."
    >
      <circle class="pf-v6-c-spinner__path" cx="50" cy="50" r="45" fill="none" />
    </svg>
  </span>

  <span class="pf-v6-c-button__icon">
    <i class="fas fa-upload" aria-hidden="true"></i>
  </span>
</button>
<br />
<button
  class="pf-v6-c-button pf-m-progress pf-m-inline pf-m-link"
  type="button"
>
  <span class="pf-v6-c-button__text">Inline loader</span>
</button>

<button
  class="pf-v6-c-button pf-m-in-progress pf-m-progress pf-m-inline pf-m-link"
  type="button"
>
  <span class="pf-v6-c-button__progress">
    <svg
      class="pf-v6-c-spinner pf-m-inline"
      role="progressbar"
      viewBox="0 0 100 100"
      aria-label="Loading..."
    >
      <circle class="pf-v6-c-spinner__path" cx="50" cy="50" r="45" fill="none" />
    </svg>
  </span>

  <span class="pf-v6-c-button__text">Inline loading</span>
</button>

```

### Counts

```html
<button class="pf-v6-c-button pf-m-primary" type="button">
  <span class="pf-v6-c-button__text">View issues</span>
  <span class="pf-v6-c-button__count">
    <span class="pf-v6-c-badge pf-m-unread">
      7
      <span class="pf-v6-screen-reader">unread messages</span>
    </span>
  </span>
</button>
<button class="pf-v6-c-button pf-m-primary" type="button">
  <span class="pf-v6-c-button__text">View issues</span>
  <span class="pf-v6-c-button__count">
    <span class="pf-v6-c-badge pf-m-read">7</span>
  </span>
</button>
<button class="pf-v6-c-button pf-m-link" type="button">
  <span class="pf-v6-c-button__text">View issues</span>
  <span class="pf-v6-c-button__count">
    <span class="pf-v6-c-badge pf-m-unread">
      7
      <span class="pf-v6-screen-reader">unread messages</span>
    </span>
  </span>
</button>
<button class="pf-v6-c-button pf-m-link" type="button">
  <span class="pf-v6-c-button__text">View issues</span>
  <span class="pf-v6-c-button__count">
    <span class="pf-v6-c-badge pf-m-read">7</span>
  </span>
</button>
<br />
<strong>disabled</strong>
<br />
<button class="pf-v6-c-button pf-m-primary" type="button" disabled>
  <span class="pf-v6-c-button__text">View issues</span>
  <span class="pf-v6-c-button__count">
    <span class="pf-v6-c-badge pf-m-unread pf-m-disabled">7</span>
  </span>
</button>
<button class="pf-v6-c-button pf-m-primary" type="button" disabled>
  <span class="pf-v6-c-button__text">View issues</span>
  <span class="pf-v6-c-button__count">
    <span class="pf-v6-c-badge pf-m-read pf-m-disabled">7</span>
  </span>
</button>
<button class="pf-v6-c-button pf-m-link" type="button" disabled>
  <span class="pf-v6-c-button__text">View issues</span>
  <span class="pf-v6-c-button__count">
    <span class="pf-v6-c-badge pf-m-unread pf-m-disabled">7</span>
  </span>
</button>
<button class="pf-v6-c-button pf-m-link" type="button" disabled>
  <span class="pf-v6-c-button__text">View issues</span>
  <span class="pf-v6-c-button__count">
    <span class="pf-v6-c-badge pf-m-read pf-m-disabled">7</span>
  </span>
</button>

```

### Plain with no padding

```html
For when a plain/icon button is placed inline with text
<button
  class="pf-v6-c-button pf-m-no-padding pf-m-plain"
  type="button"
  aria-label="More info"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-question-circle" aria-hidden="true"></i>
  </span>
</button>
.

```

### Stateful

```html
<strong>Read</strong>
<br />
<button class="pf-v6-c-button pf-m-read pf-m-stateful" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-bell" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">
    10
    <span class="pf-v6-screen-reader">items</span>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-read pf-m-stateful pf-m-clicked"
  type="button"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-bell" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">
    10
    <span class="pf-v6-screen-reader">items</span>
  </span>
</button>

<br />
<br />

<strong>Unread</strong>
<br />
<button class="pf-v6-c-button pf-m-unread pf-m-stateful" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-bell" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">
    10
    <span class="pf-v6-screen-reader">unread items</span>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-unread pf-m-stateful pf-m-clicked"
  type="button"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-bell" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">
    10
    <span class="pf-v6-screen-reader">unread items</span>
  </span>
</button>

<br />
<br />

<strong>Attention</strong>
<br />
<button class="pf-v6-c-button pf-m-attention pf-m-stateful" type="button">
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-bell" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">
    10
    <span class="pf-v6-screen-reader">unread items, needs attention</span>
  </span>
</button>

<button
  class="pf-v6-c-button pf-m-attention pf-m-stateful pf-m-clicked"
  type="button"
>
  <span class="pf-v6-c-button__icon pf-m-start">
    <i class="fas fa-bell" aria-hidden="true"></i>
  </span>
  <span class="pf-v6-c-button__text">
    10
    <span class="pf-v6-screen-reader">unread items, needs attention</span>
  </span>
</button>

```

### Favorite

A favorite button should use a plain button with the star icon. Applying `.pf-m-favorited` to the button initiates a microanimation and indicates that the item is favorited.

```html
<button
  class="pf-v6-c-button pf-m-favorite pf-m-plain"
  type="button"
  aria-label="not starred"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-star" aria-hidden="true"></i>
  </span>
</button>
<button
  class="pf-v6-c-button pf-m-favorited pf-m-favorite pf-m-plain"
  type="button"
  aria-label="starred"
>
  <span class="pf-v6-c-button__icon">
    <i class="fas fa-star" aria-hidden="true"></i>
  </span>
</button>

```

## Documentation

### Overview

Always add a modifier class to add color to the button.

### Button vs link

Semantic buttons and links are important for usability as well as accessibility. Using an `a` instead of a `button` element to perform user initiated actions should be avoided, unless absolutely necessary.

### Accessibility

| Attribute | Applied to | Outcome |
| -- | -- | -- |
| `aria-pressed="true or false"` | `.pf-v6-c-button` | Indicates that the button is a toggle. When set to true, `pf-m-active` should also be set so that the button displays in an active state. **Required when button is a toggle** |
| `aria-label="[button label text]"` | `.pf-v6-c-button.pf-m-plain` | Provides an accessible name for the button when an icon is used instead of text. **Required when icon is used with no supporting text** |
| `aria-label="[descriptive text]"` | `a.pf-v6-c-button`, `span.pf-v6-c-button.pf-m-link.pf-m-inline` | The button component's text should adequately describe its purpose. If it does not, `aria-label` can provide more detailed interaction information. |
| `disabled` | `button.pf-v6-c-button` | When a button element is used, indicates that it is unavailable and removes it from keyboard focus. **Required when button is disabled** |
| `aria-disabled=true` | `button.pf-v6-c-button` | When a button element is used, indicates that it is unavailable but does not prevent keyboard or hover interactions. Used when a disabled button provides interactive elements like a tooltip. |
| `aria-disabled=true` | `a.pf-v6-c-button.pf-m-disabled`, `span.pf-v6-c-button.pf-m-link.pf-m-inline.pf-m-disabled` | When a non-button element is used, indicates that it is unavailable. **Required when element is disabled** |
| `aria-expanded=true` | `.pf-v6-c-button.pf-m-expanded` | Indicates that the expanded content element is visible. **Required** |
| `tabindex="-1"` | `a.pf-v6-c-button.pf-m-disabled`, `span.pf-v6-c-button.pf-m-link.pf-m-inline.pf-m-disabled` | When a non-button element is used, removes it from keyboard focus. **Required when element is disabled** |
| `tabindex="0"` | `span.pf-v6-c-button.pf-m-link.pf-m-inline` | Inserts the span into the tab order of the page so that it is focusable. **Required when the element is a span** |

### Usage

| Class | Applied to | Outcome |
| -- | -- | -- |
| `.pf-v6-c-button` | `<button>, <span>` |  Initiates a button. Always use it with a modifier class. **Required** |
| `.pf-v6-c-button__icon` | `<span>` | Initiates a button icon. |
| `.pf-v6-c-button__progress` | `<span>` | Initiates a button progress container. |
| `.pf-v6-c-button__count` | `<span>` | Initiates a button count container. **Note:** Count should only be used on link buttons.|
| `.pf-m-primary` | `.pf-v6-c-button` | Modifies for primary styles. |
| `.pf-m-secondary` | `.pf-v6-c-button` | Modifies for secondary styles. |
| `.pf-m-tertiary` | `.pf-v6-c-button` | Modifies for tertiary styles. |
| `.pf-m-danger` | `.pf-v6-c-button` | Modifies for danger styles. |
| `.pf-m-warning` | `.pf-v6-c-button` | Modifies for warning styles. |
| `.pf-m-link` | `.pf-v6-c-button` | Modifies for link styles. This button has no background or border and is styled as a link. This button would commonly appear in a form and may include an icon. |
| `.pf-m-plain` | `.pf-v6-c-button` | Modifies for icon styles. This button has no background or border, uses a standard text color, and is used for `.pf-m-plain` icon buttons such as close, expand, kebab, etc. |
| `.pf-m-no-padding` | `.pf-v6-c-button.pf-m-plain` | Modifies a plain button to remove padding. This modifier should only be used when the button is inline within a sentence or block of text. Adjacent plain buttons without padding should always have spacing between them. |
| `.pf-m-inline` | `.pf-v6-c-button.pf-m-link` | Modifies for inline styles. This button is presented similar to a normal link and has no padding and is displayed inline with other inline content. When used as a `<span>`, the text will flow inline with text around it. |
| `.pf-m-block` | `.pf-v6-c-button` | Creates a block level button. |
| `.pf-m-control` | `.pf-v6-c-button` | Modifies for control styles. **Note:** This modifier should only be used when using buttons in the Input Group or Clipboard Copy components. |
| `.pf-m-expanded` | `.pf-v6-c-button.pf-m-control` | Modifies a control button for the expanded state. |
| `.pf-m-start` | `.pf-v6-c-button__icon` | Applies right spacing to an icon inside of a button when the icon comes before text. |
| `.pf-m-end` | `.pf-v6-c-button__icon` | Applies left spacing to an icon inside of a button when the icon comes after text. |
| `.pf-m-active` | `.pf-v6-c-button` | Forces display of the active state of the button. This modifier should be used when `aria-pressed` is set to true so that the button displays in an active state. |
| `.pf-m-small` | `.pf-v6-c-button` | Modifies the button for small/compact styles. |
| `.pf-m-aria-disabled` | `.pf-v6-c-button` | Modifies a button to be visually disabled, yet is still focusable. |
| `.pf-m-display-lg` | `.pf-v6-c-button`, `pf-v6-c-button.pf-m-link` | Modifies the button and link button for large display styling. For example, use this modifier to achieve "call to action" styles. |
| `.pf-m-progress` | `.pf-v6-c-button` | Indicates that the button supports the progress state. **Note:** Not used with the plain variation. |
| `.pf-m-in-progress` | `.pf-v6-c-button` | Indicates that the button is in the in progress state. |
| `.pf-m-stateful` | `.pf-v6-c-button` | Indicates that the button is used for one of read, unread, and attention states. **Note:** Always use with a modifier of `.pf-m-read`, `.pf-m-unread`, or `.pf-m-attention`. |
| `.pf-m-notify` | `.pf-v6-c-button` | Indicates that the button should show the user notification of an event. **Note:** This is intended for use with a bell icon in the notification badge. |
| `.pf-m-favorite` | `.pf-v6-c-button .pf-m-plain` | Modifies a plain button to be a favorite button. **Note:** This is intended for use with a star icon. |
| `.pf-m-favorited` | `.pf-v6-c-button .pf-m-plain .pf-m-favorite` | Modifies a favorite button to indicate that item is favorited.  |
