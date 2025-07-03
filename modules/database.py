import json
from app import db
from models.scan_result import ScanResult

def save_scan_result(scan_id, user_id, source_type, source, results):
    """
    Save scan results to the database
    
    Args:
        scan_id (str): Unique ID for the scan
        user_id (int): ID of the user who performed the scan
        source_type (str): Type of scan ('file' or 'url')
        source (str): Filename or URL scanned
        results (dict): Scan results
        
    Returns:
        bool: Success status
    """
    try:
        new_scan = ScanResult(
            id=scan_id,
            user_id=user_id,
            source_type=source_type,
            source=source,
            results=json.dumps(results)
        )
        
        db.session.add(new_scan)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"Error saving scan result: {str(e)}")
        return False

def get_scan_results(scan_id, user_id):
    """
    Retrieve scan results from the database
    
    Args:
        scan_id (str): ID of the scan to retrieve
        user_id (int): ID of the user who owns the scan
        
    Returns:
        dict: Scan results or None if not found
    """
    scan = ScanResult.query.filter_by(id=scan_id, user_id=user_id).first()
    
    if scan:
        return {
            "id": scan.id,
            "source_type": scan.source_type,
            "source": scan.source,
            "results": json.loads(scan.results),
            "timestamp": scan.timestamp.isoformat()
        }
    
    return None

def get_user_scans(user_id, limit=None):
    """
    Get all scans for a specific user
    
    Args:
        user_id (int): ID of the user
        limit (int, optional): Maximum number of scans to retrieve
        
    Returns:
        list: List of scan metadata
    """
    query = ScanResult.query.filter_by(user_id=user_id).order_by(ScanResult.timestamp.desc())
    
    if limit:
        query = query.limit(limit)
    
    scans = query.all()
    
    return [{
        "id": scan.id,
        "source_type": scan.source_type,
        "source": scan.source,
        "timestamp": scan.timestamp.isoformat(),
        "summary": json.loads(scan.results)["summary"]
    } for scan in scans]