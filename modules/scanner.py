from modules.analyzer import analyze_php_file, analyze_php_url

def scan_uploaded_file(file_path):
    """
    Scan an uploaded PHP file for vulnerabilities
    
    Args:
        file_path (str): Path to the uploaded PHP file
        
    Returns:
        dict: Scan results
    """
    return analyze_php_file(file_path)

def scan_url(url):
    """
    Scan a PHP website URL for vulnerabilities
    
    Args:
        url (str): URL of the PHP website
        
    Returns:
        dict: Scan results
    """
    return analyze_php_url(url)

def generate_report(scan_results):
    """
    Generate a comprehensive report from scan results
    
    Args:
        scan_results (dict): Scan results
        
    Returns:
        dict: Formatted report
    """
    return {
        "summary": scan_results.get("summary", {}),
        "vulnerabilities": scan_results.get("vulnerabilities", []),
        "timestamp": scan_results.get("timestamp", ""),
    }