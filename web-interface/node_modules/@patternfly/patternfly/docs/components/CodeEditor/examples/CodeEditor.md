---
id: Code editor
section: components
cssPrefix: pf-v6-c-code-editor
---import './CodeEditor.css';

## Examples

### Default

```html
<div class="pf-v6-c-code-editor">
  <div class="pf-v6-c-code-editor__header">
    <div class="pf-v6-c-code-editor__header-content">
      <div class="pf-v6-c-code-editor__controls">
        <button
          class="pf-v6-c-button pf-m-plain"
          type="button"
          aria-label="Copy to clipboard"
        >
          <span class="pf-v6-c-button__icon">
            <i class="fas fa-copy" aria-hidden="true"></i>
          </span>
        </button>
        <button
          class="pf-v6-c-button pf-m-plain"
          type="button"
          aria-label="Download code"
        >
          <span class="pf-v6-c-button__icon">
            <i class="fas fa-download" aria-hidden="true"></i>
          </span>
        </button>
        <button
          class="pf-v6-c-button pf-m-plain"
          type="button"
          aria-label="Upload code"
        >
          <span class="pf-v6-c-button__icon">
            <i class="fas fa-upload" aria-hidden="true"></i>
          </span>
        </button>
      </div>
      <div class="pf-v6-c-code-editor__header-main"></div>
    </div>
    <div class="pf-v6-c-code-editor__tab">
      <span class="pf-v6-c-code-editor__tab-icon">
        <i class="fas fa-code"></i>
      </span>
      <span class="pf-v6-c-code-editor__tab-text">HTML</span>
    </div>
  </div>
  <div class="pf-v6-c-code-editor__main">
    <div dir="ltr" class="pf-v6-c-code-editor__code">
      <pre class="pf-v6-c-code-editor__code-pre">
                code goes here
      </pre>
    </div>
  </div>
</div>

```

### Read-only

```html
<div class="pf-v6-c-code-editor pf-m-read-only">
  <div class="pf-v6-c-code-editor__header">
    <div class="pf-v6-c-code-editor__header-content">
      <div class="pf-v6-c-code-editor__controls">
        <button
          class="pf-v6-c-button pf-m-plain"
          type="button"
          aria-label="Copy to clipboard"
        >
          <span class="pf-v6-c-button__icon">
            <i class="fas fa-copy" aria-hidden="true"></i>
          </span>
        </button>
        <button
          class="pf-v6-c-button pf-m-plain"
          type="button"
          aria-label="Download code"
        >
          <span class="pf-v6-c-button__icon">
            <i class="fas fa-download" aria-hidden="true"></i>
          </span>
        </button>
        <button
          class="pf-v6-c-button pf-m-plain"
          type="button"
          aria-label="Upload code"
        >
          <span class="pf-v6-c-button__icon">
            <i class="fas fa-upload" aria-hidden="true"></i>
          </span>
        </button>
      </div>
      <div class="pf-v6-c-code-editor__header-main"></div>
    </div>
    <div class="pf-v6-c-code-editor__tab">
      <span class="pf-v6-c-code-editor__tab-icon">
        <i class="fas fa-code"></i>
      </span>
      <span class="pf-v6-c-code-editor__tab-text">HTML</span>
    </div>
  </div>
  <div class="pf-v6-c-code-editor__main">
    <div dir="ltr" class="pf-v6-c-code-editor__code">
      <pre class="pf-v6-c-code-editor__code-pre">
                code goes here
      </pre>
    </div>
  </div>
</div>

```

### Without actions

```html
<div class="pf-v6-c-code-editor">
  <div class="pf-v6-c-code-editor__header">
    <div class="pf-v6-c-code-editor__header-main"></div>
    <div class="pf-v6-c-code-editor__tab">
      <span class="pf-v6-c-code-editor__tab-icon">
        <i class="fas fa-code" aria-hidden="true"></i>
      </span>
      <span class="pf-v6-c-code-editor__tab-text">YAML</span>
    </div>
  </div>
  <div class="pf-v6-c-code-editor__main">
    <div class="pf-v6-c-code-editor__upload">
      <div class="pf-v6-c-empty-state">
        <div class="pf-v6-c-empty-state__content">
          <div class="pf-v6-c-empty-state__header">
            <div class="pf-v6-c-empty-state__icon">
              <i class="fas fa- fa-code" aria-hidden="true"></i>
            </div>
            <div class="pf-v6-c-empty-state__title">
              <h1 class="pf-v6-c-empty-state__title-text">Start editing</h1>
            </div>
          </div>

          <div
            class="pf-v6-c-empty-state__body"
          >Drag a file here or browse to upload.</div>

          <div class="pf-v6-c-empty-state__footer">
            <div class="pf-v6-c-empty-state__actions">
              <button class="pf-v6-c-button pf-m-primary" type="button">
                <span class="pf-v6-c-button__text">Browse</span>
              </button>
            </div>
            <div class="pf-v6-c-empty-state__actions">
              <button class="pf-v6-c-button pf-m-link" type="button">
                <span class="pf-v6-c-button__text">Start from scratch</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

```

### Drag file and hover over component

```html
<div class="pf-v6-c-code-editor">
  <div class="pf-v6-c-code-editor__header">
    <div class="pf-v6-c-code-editor__header-main"></div>
    <div class="pf-v6-c-code-editor__tab">
      <span class="pf-v6-c-code-editor__tab-icon">
        <i class="fas fa-code" aria-hidden="true"></i>
      </span>
      <span class="pf-v6-c-code-editor__tab-text">YAML</span>
    </div>
  </div>
  <div class="pf-v6-c-code-editor__main pf-m-drag-hover">
    <div class="pf-v6-c-code-editor__upload">
      <div class="pf-v6-c-empty-state">
        <div class="pf-v6-c-empty-state__content">
          <div class="pf-v6-c-empty-state__header">
            <div class="pf-v6-c-empty-state__icon">
              <i class="fas fa- fa-code" aria-hidden="true"></i>
            </div>
            <div class="pf-v6-c-empty-state__title">
              <h1 class="pf-v6-c-empty-state__title-text">Start editing</h1>
            </div>
          </div>

          <div
            class="pf-v6-c-empty-state__body"
          >Drag a file here or browse to upload.</div>

          <div class="pf-v6-c-empty-state__footer">
            <div class="pf-v6-c-empty-state__actions">
              <button class="pf-v6-c-button pf-m-primary" type="button">
                <span class="pf-v6-c-button__text">Browse</span>
              </button>
            </div>
            <div class="pf-v6-c-empty-state__actions">
              <button class="pf-v6-c-button pf-m-link" type="button">
                <span class="pf-v6-c-button__text">Start from scratch</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

```

### With optional header content and keyboard shortcuts

```html
<div class="pf-v6-c-code-editor">
  <div class="pf-v6-c-code-editor__header">
    <div class="pf-v6-c-code-editor__header-content">
      <div class="pf-v6-c-code-editor__controls">
        <button
          class="pf-v6-c-button pf-m-plain"
          type="button"
          aria-label="Copy to clipboard"
        >
          <span class="pf-v6-c-button__icon">
            <i class="fas fa-copy" aria-hidden="true"></i>
          </span>
        </button>
        <button
          class="pf-v6-c-button pf-m-plain"
          type="button"
          aria-label="Download code"
        >
          <span class="pf-v6-c-button__icon">
            <i class="fas fa-download" aria-hidden="true"></i>
          </span>
        </button>
        <button
          class="pf-v6-c-button pf-m-plain"
          type="button"
          aria-label="Upload code"
        >
          <span class="pf-v6-c-button__icon">
            <i class="fas fa-upload" aria-hidden="true"></i>
          </span>
        </button>
      </div>
      <div class="pf-v6-c-code-editor__header-main">Header main content</div>
      <div class="pf-v6-c-code-editor__keyboard-shortcuts">
        <button class="pf-v6-c-button pf-m-link" type="button">
          <span class="pf-v6-c-button__icon pf-m-start">
            <i class="fas fa-question-circle" aria-hidden="true"></i>
          </span>
          <span class="pf-v6-c-button__text">View shortcuts</span>
        </button>
      </div>
    </div>
    <div class="pf-v6-c-code-editor__tab">
      <span class="pf-v6-c-code-editor__tab-icon">
        <i class="fas fa-code"></i>
      </span>
      <span class="pf-v6-c-code-editor__tab-text">HTML</span>
    </div>
  </div>
  <div class="pf-v6-c-code-editor__main">
    <div dir="ltr" class="pf-v6-c-code-editor__code">
      <pre class="pf-v6-c-code-editor__code-pre">
                code goes here
      </pre>
    </div>
  </div>
</div>

```

### With optional code editor container

This is an extra container used in React to prevent event propagation if upload is enabled or there is a provided empty state.

```html
<div class="pf-v6-c-code-editor">
  <div role="presentation" tabindex="0" class="pf-v6-c-code-editor__container">
    <div class="pf-v6-c-code-editor__header">
      <div class="pf-v6-c-code-editor__header-content">
        <div class="pf-v6-c-code-editor__controls">
          <button
            class="pf-v6-c-button pf-m-plain"
            type="button"
            aria-label="Copy to clipboard"
          >
            <span class="pf-v6-c-button__icon">
              <i class="fas fa-copy" aria-hidden="true"></i>
            </span>
          </button>
          <button
            class="pf-v6-c-button pf-m-plain"
            type="button"
            aria-label="Download code"
          >
            <span class="pf-v6-c-button__icon">
              <i class="fas fa-download" aria-hidden="true"></i>
            </span>
          </button>
          <button
            class="pf-v6-c-button pf-m-plain"
            type="button"
            aria-label="Upload code"
          >
            <span class="pf-v6-c-button__icon">
              <i class="fas fa-upload" aria-hidden="true"></i>
            </span>
          </button>
        </div>
      </div>
      <div class="pf-v6-c-code-editor__tab">
        <span class="pf-v6-c-code-editor__tab-icon">
          <i class="fas fa-code"></i>
        </span>
        <span class="pf-v6-c-code-editor__tab-text">HTML</span>
      </div>
    </div>
    <div class="pf-v6-c-code-editor__main">
      <div class="pf-v6-c-code-editor__upload">
        <div class="pf-v6-c-empty-state">
          <div class="pf-v6-c-empty-state__content">
            <div class="pf-v6-c-empty-state__header">
              <div class="pf-v6-c-empty-state__icon">
                <i class="fas fa- fa-code" aria-hidden="true"></i>
              </div>
              <div class="pf-v6-c-empty-state__title">
                <h1 class="pf-v6-c-empty-state__title-text">Start editing</h1>
              </div>
            </div>

            <div
              class="pf-v6-c-empty-state__body"
            >Drag a file here or browse to upload.</div>

            <div class="pf-v6-c-empty-state__footer">
              <div class="pf-v6-c-empty-state__actions">
                <button class="pf-v6-c-button pf-m-primary" type="button">
                  <span class="pf-v6-c-button__text">Browse</span>
                </button>
              </div>
              <div class="pf-v6-c-empty-state__actions">
                <button class="pf-v6-c-button pf-m-link" type="button">
                  <span class="pf-v6-c-button__text">Start from scratch</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

```

### With full height modifier

```html
<div class="pf-v6-c-code-editor pf-m-full-height">
  <div class="pf-v6-c-code-editor__header">
    <div class="pf-v6-c-code-editor__header-content">
      <div class="pf-v6-c-code-editor__controls">
        <button
          class="pf-v6-c-button pf-m-plain"
          type="button"
          aria-label="Copy to clipboard"
        >
          <span class="pf-v6-c-button__icon">
            <i class="fas fa-copy" aria-hidden="true"></i>
          </span>
        </button>
        <button
          class="pf-v6-c-button pf-m-plain"
          type="button"
          aria-label="Download code"
        >
          <span class="pf-v6-c-button__icon">
            <i class="fas fa-download" aria-hidden="true"></i>
          </span>
        </button>
        <button
          class="pf-v6-c-button pf-m-plain"
          type="button"
          aria-label="Upload code"
        >
          <span class="pf-v6-c-button__icon">
            <i class="fas fa-upload" aria-hidden="true"></i>
          </span>
        </button>
      </div>
      <div class="pf-v6-c-code-editor__header-main">Header main content</div>
      <div class="pf-v6-c-code-editor__keyboard-shortcuts">
        <button class="pf-v6-c-button pf-m-link" type="button">
          <span class="pf-v6-c-button__icon pf-m-start">
            <i class="fas fa-question-circle" aria-hidden="true"></i>
          </span>
          <span class="pf-v6-c-button__text">View shortcuts</span>
        </button>
      </div>
    </div>
    <div class="pf-v6-c-code-editor__tab">
      <span class="pf-v6-c-code-editor__tab-icon">
        <i class="fas fa-code"></i>
      </span>
      <span class="pf-v6-c-code-editor__tab-text">HTML</span>
    </div>
  </div>
  <div class="pf-v6-c-code-editor__main">
    <div dir="ltr" class="pf-v6-c-code-editor__code">
      <pre class="pf-v6-c-code-editor__code-pre">
                code goes here
      </pre>
    </div>
  </div>
</div>

```

## Documentation

### Usage

| Class                                      | Applied to | Outcome                                                                                       |
| ------------------------------------------ | ---------- | --------------------------------------------------------------------------------------------- |
| `.pf-v6-c-code-editor`                     | `<div>`    | Initiates the code editor component. **Required**                                             |
| `.pf-v6-c-code-editor__header`             | `<div>`    | Initiates the code editor header used for the controls and tab elements. **Required**         |
| `.pf-v6-c-code-editor__header-content`     | `<div>`    | Initiates the code editor header content used for the controls and tab elements. **Required** |
| `.pf-v6-c-code-editor__main`               | `<div>`    | Initiates the main container for a code editor e.g. Monaco **Required**                       |
| `.pf-v6-c-code-editor__code`               | `<div>`    | Initiates the container for code without a JS code editor. Comes with PatternFly styling.     |
| `.pf-v6-c-code-editor__controls`           | `<div>`    | Initiates the code editor controls.                                                           |
| `.pf-v6-c-code-editor__header-main`        | `<div>`    | Initiates the code editor header content area.                                                |
| `.pf-v6-c-code-editor__keyboard-shortcuts` | `<div>`    | Initiates the code editor header keyboard shortcuts area.                                     |
| `.pf-v6-c-code-editor__tab`                | `<div>`    | Initiates the code editor tab.                                                                |
| `.pf-v6-c-code-editor__tab-text`           | `<span>`   | Initiates the code editor tab text.                                                           |
| `.pf-v6-c-code-editor__tab-icon`           | `<span>`   | Initiates the code editor tab icon.                                                           |
| `.pf-v6-c-code-editor__upload`             | `<div>`    | Initiates the code editor upload border.                                                      |
| `.pf-v6-c-code-editor__container`             | `<div>`    | Initiates the container used inside `.pf-v6-c-code-editor` in PatternFly React. This is used in PatternFly React to prevent event propagation if upload is enabled or there is a provided empty state.                                                      |
| `.pf-m-full-height`             | `.pf-v6-c-code-editor`    | Modifies for full-height style.                                                   |
