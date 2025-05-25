from fastapi import FastAPI, Depends, HTTPException, Security, status, Query
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field, ConfigDict, validator, field_validator
from pymongo import MongoClient, DESCENDING
from bson import ObjectId
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime

# --- 1. API Key Configuration ---
# 重要: 以下のAPI_KEYを実際に生成した100文字のランダムな文字列に置き換えてください。
API_KEY = "YOUR_GENERATED_100_CHAR_RANDOM_API_KEY_HERE_REPLACE_ME"
API_KEY_NAME = "X-API-Key"

api_key_header_auth = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def get_api_key(api_key_header: Optional[str] = Security(api_key_header_auth)):
    if api_key_header == API_KEY:
        return api_key_header
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )

# --- 2. MongoDB Configuration ---
MONGO_CLIENT_URL = "mongodb://localhost:27017/"
DATABASE_NAME = "log_database_fastapi"
LOG_COLLECTION_NAME = "logs"

client = MongoClient(MONGO_CLIENT_URL)
db = client[DATABASE_NAME]
log_collection = db[LOG_COLLECTION_NAME]

# Create index for timestamp for better query performance on logs
log_collection.create_index([("timestamp", DESCENDING)])
log_collection.create_index([("resourceId", 1)])
log_collection.create_index([("level", 1)])
log_collection.create_index([("traceId", 1)])


# --- 3. Pydantic Models ---

# Helper for ObjectId validation and serialization if needed,
# but Pydantic v2 handles ObjectId better with json_encoders.

class LogBase(BaseModel):
    level: str = Field(..., examples=["INFO", "ERROR", "DEBUG"])
    message: str = Field(..., examples=["User logged in successfully."])
    resourceId: str = Field(..., examples=["service-A/instance-001"])
    traceId: Optional[str] = Field(default=None, examples=["abc-123-xyz-789"])
    spanId: Optional[str] = Field(default=None, examples=["span-456"])
    commit: Optional[str] = Field(default=None, examples=["a1b2c3d"])
    metadata: Optional[Dict[str, Any]] = Field(default=None, examples=[{"userId": "user123", "ipAddress": "192.168.1.100"}])

class LogCreate(LogBase):
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class LogEntryResponse(LogBase):
    id: str = Field(alias="_id") # For response, _id is aliased to id and converted to str
    timestamp: datetime

    model_config = ConfigDict(
        populate_by_name=True,  # Allows use of _id from MongoDB for the 'id' field via alias
        arbitrary_types_allowed=True, # Important for types like ObjectId if they were fields
        json_encoders={
            ObjectId: lambda oid: str(oid), # Serialize ObjectId to str
            datetime: lambda dt: dt.isoformat() # Ensure datetime is in ISO format
        }
    )

    # Ensure _id (ObjectId) is converted to str for the 'id' field
    @field_validator('id', mode='before')
    @classmethod
    def convert_objectid_to_str(cls, value):
        if isinstance(value, ObjectId):
            return str(value)
        return value

class MongoQuery(BaseModel):
    filter: Optional[Dict[str, Any]] = Field(default_factory=dict, examples=[{"level": "ERROR", "resourceId": "service-B"}])
    projection: Optional[Dict[str, Any]] = Field(default=None, examples=[{"message": 1, "timestamp": 1, "_id": 0}])
    sort: Optional[List[Tuple[str, int]]] = Field(default_factory=lambda: [("timestamp", DESCENDING)], examples=[[("timestamp", -1)]])
    limit: int = Field(default=100, ge=0, description="Limit for results. 0 means no limit.") # ge=0 means 0 is allowed (for no limit)
    skip: int = Field(default=0, ge=0, description="Number of documents to skip.")


# --- 4. FastAPI Application ---
app = FastAPI(
    title="Mongo Log API",
    description="API for storing and querying logs in MongoDB. Requires X-API-Key header for authentication.",
    version="1.0.0",
    dependencies=[Depends(get_api_key)] # Apply API key auth to all routes
)

# --- 5. Endpoints ---

@app.post("/logs/", response_model=LogEntryResponse, status_code=status.HTTP_201_CREATED, summary="Create a Single Log Entry")
async def create_log_entry(log: LogCreate):
    """
    Inserts a single log entry into the database.
    The `timestamp` is automatically set to the current UTC time if not provided.
    """
    log_dict = log.model_dump()
    result = log_collection.insert_one(log_dict)
    created_log = log_collection.find_one({"_id": result.inserted_id})
    if created_log:
        return LogEntryResponse.model_validate(created_log) # Use model_validate for Pydantic v2
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Log entry could not be created or retrieved.")

@app.post("/logs/bulk/", response_model=List[LogEntryResponse], status_code=status.HTTP_201_CREATED, summary="Create Multiple Log Entries")
async def create_bulk_log_entries(logs: List[LogCreate]):
    """
    Inserts multiple log entries into the database in a single operation.
    """
    if not logs:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No log entries provided in the list.")
    log_dicts = [log.model_dump() for log in logs]
    result = log_collection.insert_many(log_dicts)
    inserted_ids = result.inserted_ids
    created_logs_cursor = log_collection.find({"_id": {"$in": inserted_ids}})
    return [LogEntryResponse.model_validate(log_doc) for log_doc in created_logs_cursor]

@app.get("/logs/{log_id}", response_model=LogEntryResponse, summary="Get a Specific Log Entry by ID")
async def get_log_entry_by_id(log_id: str):
    """
    Retrieves a specific log entry using its unique ID.
    """
    if not ObjectId.is_valid(log_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid log ID format: {log_id}")
    log_doc = log_collection.find_one({"_id": ObjectId(log_id)})
    if log_doc:
        return LogEntryResponse.model_validate(log_doc)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Log entry with ID {log_id} not found.")

@app.get("/logs/", response_model=List[LogEntryResponse], summary="Search Log Entries")
async def search_log_entries(
    level: Optional[str] = Query(default=None, description="Filter by log level (e.g., INFO, ERROR)."),
    message_contains: Optional[str] = Query(default=None, description="Filter by messages containing this text (case-insensitive)."),
    resourceId: Optional[str] = Query(default=None, description="Filter by resource ID."),
    traceId: Optional[str] = Query(default=None, description="Filter by trace ID."),
    start_time: Optional[datetime] = Query(default=None, description="Include logs from this timestamp (ISO format)."),
    end_time: Optional[datetime] = Query(default=None, description="Include logs up to this timestamp (ISO format)."),
    limit: int = Query(default=100, ge=0, description="Maximum number of log entries to return. 0 for no limit."),
    skip: int = Query(default=0, ge=0, description="Number of log entries to skip (for pagination)."),
    sort_by: str = Query(default="timestamp", description="Field to sort by."),
    sort_order: int = Query(default=-1, description="Sort order: 1 for ascending, -1 for descending.")
):
    """
    Searches for log entries based on specified criteria with pagination and sorting.
    """
    query_filter: Dict[str, Any] = {}
    if level:
        query_filter["level"] = level
    if message_contains:
        query_filter["message"] = {"$regex": message_contains, "$options": "i"}
    if resourceId:
        query_filter["resourceId"] = resourceId
    if traceId:
        query_filter["traceId"] = traceId

    time_filter = {}
    if start_time:
        time_filter["$gte"] = start_time
    if end_time:
        time_filter["$lte"] = end_time
    if time_filter:
        query_filter["timestamp"] = time_filter

    # Ensure sort_order is either 1 or -1
    if sort_order not in [1, -1]:
        sort_order = -1 # Default to descending if invalid value

    logs_cursor = log_collection.find(query_filter).sort(sort_by, sort_order).skip(skip)
    if limit > 0: # Only apply limit if it's greater than 0
        logs_cursor = logs_cursor.limit(limit)

    return [LogEntryResponse.model_validate(log_doc) for log_doc in logs_cursor]

@app.put("/logs/{log_id}", response_model=LogEntryResponse, summary="Update a Log Entry")
async def update_log_entry(log_id: str, log_update: LogBase): # LogBase doesn't include timestamp, so it won't be updated by default
    """
    Updates an existing log entry. Fields not provided in the request body will remain unchanged.
    The `timestamp` of the log entry is typically not modified by this operation.
    """
    if not ObjectId.is_valid(log_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid log ID format: {log_id}")

    update_data = log_update.model_dump(exclude_unset=True) # Only include fields that were actually set in the request
    if not update_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No update data provided.")

    result = log_collection.update_one({"_id": ObjectId(log_id)}, {"$set": update_data})

    if result.matched_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Log entry with ID {log_id} not found.")

    updated_log_doc = log_collection.find_one({"_id": ObjectId(log_id)})
    if updated_log_doc:
        return LogEntryResponse.model_validate(updated_log_doc)
    # This case should ideally not be reached if matched_count > 0
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Log entry updated but could not be retrieved.")


@app.delete("/logs/{log_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a Log Entry")
async def delete_log_entry_by_id(log_id: str):
    """
    Deletes a specific log entry by its ID.
    Returns HTTP 204 No Content on successful deletion.
    """
    if not ObjectId.is_valid(log_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid log ID format: {log_id}")

    result = log_collection.delete_one({"_id": ObjectId(log_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Log entry with ID {log_id} not found.")
    return # FastAPI handles 204 response

@app.post("/query/", response_model=List[Dict[str,Any]], summary="Execute a MongoDB Find Query")
async def execute_raw_query(query: MongoQuery):
    """
    Executes a MongoDB `find`-like query directly on the logs collection.
    **WARNING**: Use with caution. While limited to `find` operations, ensure filters are appropriate.

    - **filter**: MongoDB query filter document.
    - **projection**: MongoDB projection document (e.g., `{"message": 1, "timestamp": 1}` to include, `{"_id": 0}` to exclude).
    - **sort**: List of (key, direction) tuples (e.g., `[["timestamp", -1]]`).
    - **limit**: Maximum number of documents to return (0 for no limit).
    - **skip**: Number of documents to skip.
    """
    try:
        cursor = log_collection.find(
            filter=query.filter,
            projection=query.projection if query.projection is not None else None # Pass None if empty, not {}
        )
        if query.sort:
            cursor = cursor.sort(query.sort)
        if query.skip > 0:
            cursor = cursor.skip(query.skip)
        if query.limit > 0: # pymongo's limit(0) means no limit
            cursor = cursor.limit(query.limit)
        
        # Manually serialize results including ObjectId to string for _id
        results = []
        for doc in cursor:
            if "_id" in doc and isinstance(doc["_id"], ObjectId):
                doc["_id"] = str(doc["_id"])
            # Ensure datetime objects are serialized to ISO format strings
            for key, value in doc.items():
                if isinstance(value, datetime):
                    doc[key] = value.isoformat()
            results.append(doc)
        return results
    except Exception as e:
        # Log the exception for debugging
        print(f"Error executing query: {e}") # Consider proper logging
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Error executing query: {str(e)}")

# --- To run this application (save as main.py): ---
# 1. Make sure you have MongoDB running on localhost:27017.
# 2. Replace 'YOUR_GENERATED_100_CHAR_RANDOM_API_KEY_HERE_REPLACE_ME' with your actual API key.
# 3. Install necessary libraries:
#    pip install fastapi uvicorn pymongo "pydantic[email]" python-jose[cryptography] passlib[bcrypt]
# 4. Run with Uvicorn:
#    uvicorn main:app --reload