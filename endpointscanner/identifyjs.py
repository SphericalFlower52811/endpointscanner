'''
This file contains the two functions to identify the JS Stack used by the website.
'''

def identify_javascript_type(html, headers=None, current_stack=None):
    if current_stack is None:
        current_stack = []
    html_lower = html.lower() if html else ""
        
    # Next.js
    if any(term in html for term in ['data-next-head', 'script id="__NEXT_DATA__"', 'next-head-count', '_next/', '_next/data']):
        if "Next.js" not in current_stack: current_stack.append("Next.js")
    # React
    if 'data-reactroot' in html or 'react-dom' in html_lower:
        if "React" not in current_stack: current_stack.append("React")
    # Vue / Angular / Nuxt
    if 'v-bind' in html: 
        if "Vue.js" not in current_stack: current_stack.append("Vue.js")
    if 'id="__nuxt"' in html or 'window.__NUXT__' in html: 
        if "Nuxt.js (Vue)" not in current_stack: current_stack.append("Nuxt.js (Vue)")
    if '<app-root' in html or 'ng-version' in html or '_nghost-' in html or 'ng-app' in html_lower: 
        if "Angular" not in current_stack: current_stack.append("Angular")
        
    # Astro
    if any(term in html_lower for term in ['_astro/', 'data-astro-']):
        if "Astro" not in current_stack: current_stack.append("Astro")
    # Gatsby
    if 'gatsby-ssr' in html_lower or 'id="___gatsby"' in html_lower or '__gatsby' in html_lower:
        if "Gatsby" not in current_stack: current_stack.append("Gatsby")
    # Remix
    if 'window.__remixcontext' in html_lower:
        if "Remix" not in current_stack: current_stack.append("Remix")
    #Svelte
    if 'data-sveltekit-preload-data' in html_lower:
        if "Svelte" not in current_stack: current_stack.append("Svelte")
        if "Sveltekit (Svelte)" not in current_stack: 
            current_stack.append("Sveltekit (Svelte)")
        
    # jQuery
    if any(term in html_lower for term in ['jquery.min', 'jquery-', '/jquery/']):
        if "jQuery" not in current_stack: current_stack.append("jQuery")
    # Alpine.js
    if 'alpine.min.js' in html_lower or 'x-data=' in html_lower:
        if "Alpine.js" not in current_stack: current_stack.append("Alpine.js")
    # Backbone.js
    if 'backbone.js' in html_lower or 'backbone-min.js' in html_lower:
        if "Backbone.js" not in current_stack: current_stack.append("Backbone.js")
    # Ember.js
    if 'ember.js' in html_lower or 'ember-template-' in html_lower:
        if "Ember.js" not in current_stack: current_stack.append("Ember.js")
        
    # Forem (Ruby on Rails)
    if any(term in html_lower for term in ['forem:name', 'forem:logo', 'forem:domain', 'window.forem']):
        if "Forem" not in current_stack: current_stack.append("Forem")
        if "Ruby on Rails (Backend)" not in current_stack: current_stack.append("Ruby on Rails (Backend)")

    # js stacks that can only be detected via header in requests
    if headers:
        # Node.js
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'express' in powered_by or 'node' in powered_by:
            node_label = f"Node.js ({powered_by.capitalize()})"
            if node_label not in current_stack: current_stack.append(node_label)
            
        # Ruby on Rails
        server_header = headers.get('Server', '').lower()
        if any(term in server_header for term in ['phusion passenger', 'puma']):
            if "Ruby on Rails (Backend)" not in current_stack: current_stack.append("Ruby on Rails (Backend)")
        if 'x-rack-cache' in headers or '_rails_session' in headers.get('Set-Cookie', '').lower():
            if "Ruby on Rails (Backend)" not in current_stack: current_stack.append("Ruby on Rails (Backend)")
            
        powered_by_clean = powered_by.strip()
        server_header_clean = server_header.strip()
        if powered_by_clean == 'deno' or server_header_clean == 'deno':
            if "Deno (Runtime)" not in current_stack: current_stack.append("Deno (Runtime)")
            
        if powered_by_clean == 'bun' or server_header_clean == 'bun':
            if "Bun (Runtime)" not in current_stack: current_stack.append("Bun (Runtime)")

    #Build Tools
    if any(term in html_lower for term in ['@vite/client', 'vite-plugin', 'src="/@vite']):
        if "Vite" not in current_stack: current_stack.append("Vite")
    if 'webpack' in html_lower: 
        if "Webpack" not in current_stack: current_stack.append("Webpack")
        
    return current_stack


def identify_javascript_type_two(javascript_content, current_stack):
    js_lower = javascript_content.lower() if javascript_content else ""
    
    if any(term in js_lower for term in ['__reactfiber', '__reactevents', 'Symbol.for("react.transitional.element")', 'Symbol.for("react.lazy")']):
        if "React" not in current_stack: current_stack.append("React")
    if 'window.__vue__' in js_lower or '__vue_app__' in js_lower or 'vue_vue_type_script_setup_true_lang-' in js_lower:
        if "Vue.js" not in current_stack: current_stack.append("Vue.js")
    if 'ngdevmode' in js_lower or 'ɵɵdefinecomponent' in js_lower:
        if "Angular" not in current_stack: current_stack.append("Angular")
    if '_nuxt/static/' in js_lower or 'window.__nuxt__' in js_lower:
        if "Nuxt.js (Vue)" not in current_stack: current_stack.append("Nuxt.js (Vue)")
    # Svelte
    if 'create_fragment(' in js_lower or 'init(this, component, ' in js_lower:
        if "Svelte" not in current_stack: current_stack.append("Svelte")
    # SolidJS
    if '_$createcomponent' in js_lower or 'solid-js/web' in js_lower:
        if "SolidJS" not in current_stack: current_stack.append("SolidJS")
    if 'alpine.' in js_lower or 'alpine:init' in js_lower:
        if "Alpine.js" not in current_stack: current_stack.append("Alpine.js")
    if 'fn.jquery' in js_lower:
        if "jQuery" not in current_stack: current_stack.append("jQuery")
    # Backbone & Ember
    if 'backbone.model.extend' in js_lower or 'backbone.view.extend' in js_lower:
        if "Backbone.js" not in current_stack: current_stack.append("Backbone.js")
    if 'ember.component' in js_lower or 'ember.application' in js_lower:
        if "Ember.js" not in current_stack: current_stack.append("Ember.js")
        
    #Redux
    if any(term in js_lower for term in ['createStore', 'combineReducers', '@@redux/']):
        if "Redux" not in current_stack: current_stack.append("Redux")

    if 'data-astro-' in js_lower or '/_astro/' in js_lower:
        if "Astro" not in current_stack: current_stack.append("Astro")
    if '___gatsby' in js_lower or '__gatsby' in js_lower:
        if "Gatsby" not in current_stack: current_stack.append("Gatsby")
    if '_next/static/chunks' in js_lower:
        if "Next.js" not in current_stack: current_stack.append("Next.js")
    if 'window.__remixcontext' in js_lower or 'remix-manifest' in js_lower:
        if "Remix" not in current_stack: current_stack.append("Remix")

    # BuildTools
    if any(term in js_lower for term in ['__vite__', '__vite_plugin_react_preamble_installed__']):
        if "Vite" not in current_stack: current_stack.append("Vite")
    if 'webpackjsonp' in js_lower or '__webpack_require__' in js_lower:
        if "Webpack" not in current_stack: current_stack.append("Webpack")
    if 'parcelrequire' in js_lower:
        if "Parcel" not in current_stack: current_stack.append("Parcel")
    if 'globalthis.turbopack' in js_lower or '__turbopack_' in js_lower:
        if "Turbopack" not in current_stack: current_stack.append("Turbopack")

    return current_stack