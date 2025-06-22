def detect_cms(response):
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    content = response.text.lower()

    if 'x-drupal-cache' in headers or 'drupal' in headers.get('x-generator', ''):
        return "Drupal"
    if 'x-wix-request-id' in headers:
        return "Wix"
    if 'wordpress' in headers.get('x-powered-by', '') or "wp-content" in content or "wp-includes" in content:
        return "WordPress"
    if "/sites/default/files/" in content:
        return "Drupal"
    if "joomla!" in content:
        return "Joomla"
    if "shopify" in content:
        return "Shopify"
    if "squarespace.com" in content:
        return "Squarespace"
    if "data-cms" in content:
        return "Webflow"

    return None
