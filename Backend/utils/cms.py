def detect_cms(response):
    headers = response.headers
    content = response.text.lower()

    if 'x-drupal-cache' in headers or 'drupal' in headers.get('x-generator', '').lower():
        return "Drupal"
    elif 'x-wix-request-id' in headers:
        return "Wix"
    elif 'wordpress' in headers.get('x-powered-by', '').lower() or "wp-content" in content or "wp-includes" in content:
        return "WordPress"
    elif "/sites/default/files/" in content:
        return "Drupal"
    elif "joomla!" in content:
        return "Joomla"
    elif "shopify" in content:
        return "Shopify"
    elif "squarespace.com" in content:
        return "Squarespace"
    elif "data-cms" in content:
        return "Webflow"
    return None
