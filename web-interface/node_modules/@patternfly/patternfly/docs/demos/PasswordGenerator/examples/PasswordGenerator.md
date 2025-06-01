---
id: 'Password generator'
section: components
---## Examples

### Provide a generated password

```html
<form class="pf-v6-c-form" novalidate>
  <div class="pf-v6-c-form__group">
    <div class="pf-v6-c-form__group-label pf-m-info">
      <div class="pf-v6-c-form__group-label-main"><label
          class="pf-v6-c-form__label"
          for="password-generator-demo--initial-password"
        >
          <span class="pf-v6-c-form__label-text">Password</span>&nbsp;<span class="pf-v6-c-form__label-required" aria-hidden="true">&#42;</span></label>&nbsp;<span class="pf-v6-c-form__group-label-help">
          <span
            class="pf-v6-c-button pf-m-no-padding pf-m-plain"
            type="button"
            role="button"
            tabindex="0"
            aria-label="More information for password field"
            aria-describedby="password-generator-demo--initial-password"
          >
            <span class="pf-v6-c-button__icon">
              <i class="fas fa-question-circle" aria-hidden="true"></i>
            </span>
          </span></span>
      </div>
      <div class="pf-v6-c-form__group-label-info"></div>
    </div>
    <div class="pf-v6-c-form__group-control">
      <div class="pf-v6-c-input-group">
        <div class="pf-v6-c-input-group__item pf-m-fill">
          <span class="pf-v6-c-form-control pf-m-required">
            <input
              required
              type="password"
              id="password-generator-demo--initial-password"
              name="password-generator-demo--initial-password"
              aria-label="Password input"
              value
              placeholder="Password"
            />
          </span>
        </div>
        <div class="pf-v6-c-input-group__item">
          <button
            class="pf-v6-c-button pf-m-control"
            type="button"
            aria-label="Show password"
          >
            <span class="pf-v6-c-button__icon">
              <i class="fas fa-eye" aria-hidden="true"></i>
            </span>
          </button>
        </div>
      </div>
      <div class="pf-v6-c-menu">
        <div class="pf-v6-c-menu__content">
          <ul class="pf-v6-c-menu__list" role="menu">
            <li class="pf-v6-c-menu__list-item" role="none">
              <button class="pf-v6-c-menu__item" type="button" role="menuitem">
                <span class="pf-v6-c-menu__item-main">
                  <span
                    class="pf-v6-c-menu__item-text"
                  >Use suggested password: fqu9kKe676JmKt2</span>
                </span>
              </button>
              <div class="pf-v6-c-menu__item-action">
                <button
                  class="pf-v6-c-button pf-m-plain"
                  type="button"
                  role="menuitem"
                  aria-label="Generate a new suggested password"
                >
                  <span class="pf-v6-c-button__icon">
                    <i class="fas fa-fw fa-redo" aria-hidden="true"></i>
                  </span>
                </button>
              </div>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</form>

```

## Documentation

This demo shows how to use a menu in conjunction with a form input to provide a generated password and an associated button for refresh.
