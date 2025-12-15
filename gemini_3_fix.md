# Vulnerability Fixes for gemini_3.csv

## CRAPI-001: BOLA in Vehicle Location
**File:** `services/identity/src/main/java/com/crapi/controller/VehicleController.java`
**Location:** `getLocationBOLA` method (Lines 121-128)

**Issue:** The endpoint allows any user to retrieve the location of any vehicle by providing its `carId`, without verifying ownership.

**Fix:**
Modify the method to verify that the requesting user owns the vehicle before returning the location.

```java
    @GetMapping("/vehicle/{carId}/location")
    public ResponseEntity<?> getLocationBOLA(@PathVariable("carId") UUID carId, HttpServletRequest request) {
        // Fix: Check if the user owns the vehicle
        List<VehicleDetails> userVehicles = vehicleService.getVehicleDetails(request);
        boolean isOwner = userVehicles.stream().anyMatch(v -> v.getUuid().equals(carId));
        
        if (!isOwner) {
             return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new CRAPIResponse(UserMessage.DID_NOT_GET_VEHICLE_FOR_USER));
        }

        VehicleLocationResponse vehicleDetails = vehicleService.getVehicleLocation(carId);
        if (vehicleDetails != null) return ResponseEntity.ok().body(vehicleDetails);
        else
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new CRAPIResponse(UserMessage.DID_NOT_GET_VEHICLE_FOR_USER));
    }
```

---

## CRAPI-002: Remote Code Execution (Command Injection)
**File:** `services/identity/src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java`
**Location:** `convertVideo` method (Lines 240-244)

**Issue:** User input `conversion_params` is directly injected into a shell command.

**Fix:**
Remove the shell injection capability. Use a predefined set of allowed parameters or a safer video conversion library. If using shell commands is necessary for the exercise, strictly validate against an allowlist.

```java
          // ... inside convertVideo method ...
          if (optionalProfileVideo.isPresent()) { // Removed enable_shell_injection check to enforce security
            profileVideo = optionalProfileVideo.get();
            if (ProfileValidator.checkContains(profileVideo.getConversion_params())) {
              return new CRAPIResponse(UserMessage.CONVERSION_VIDEO_OK, 200);
            } else if (profileVideo.getConversion_params().equalsIgnoreCase("-v codec h264")) {
              return new CRAPIResponse(UserMessage.CONVERT_VIDEO_BASH_COMMAND_TRIGGERED, 200);
            } 
            // Removed the vulnerable 'else if' block that allowed arbitrary command execution
            
            return new CRAPIResponse(UserMessage.CONVERT_VIDEO_INTERNAL_ERROR, 500);
          }
```

---

## CRAPI-003: NoSQL Injection in Coupons
**File:** `services/community/api/controllers/coupon_controller.go`
**Location:** `ValidateCoupon` method (Lines 94)

**Issue:** The endpoint unmarshals arbitrary JSON into a BSON map and passes it to the database query, allowing injection of MongoDB operators.

**Fix:**
Define a struct for the input and copy only allowed fields to the query.

```go
// In services/community/api/controllers/coupon_controller.go

func (s *Server) ValidateCoupon(w http.ResponseWriter, r *http.Request) {
    // Fix: Use specific struct instead of generic bson.M
    type CouponRequest struct {
        CouponCode string `json:"coupon_code"`
    }
    var req CouponRequest

    body, err := io.ReadAll(r.Body)
    // ... error handling ...

    err = json.Unmarshal(body, &req)
    // ... error handling ...

    // Fix: Construct bson.M explicitly
    query := bson.M{"coupon_code": req.CouponCode}
    couponData, err := models.ValidateCode(s.Client, s.DB, query)

    // ... rest of function
}
```

---

## CRAPI-004: Race Condition / Identity Spoofing
**File:** `services/community/api/models/user.go`
**Location:** Global variables (Lines 32-37)

**Issue:** Request-scoped data is stored in package-level global variables, causing race conditions where users can see each other's data.

**Fix:**
Remove global variables and return the data from `FindAuthorByEmail`.

```go
// services/community/api/models/user.go

// Remove these global variables
// var autherID uint64
// var nickname string
// ...

// Update FindAuthorByEmail signature to return the Author object or specific fields
func FindAuthorByEmail(email string, db *gorm.DB) (*Author, error) {
    // ... fetch logic ...
    
    // Construct and return Author object locally
    author := &Author{
        Email: email,
        Nickname: name,
        Picurl: picUrl,
        VehicleID: uuid,
    }
    return author, nil
}
```

---

## CRAPI-005: JWT Algorithm Confusion
**File:** `services/identity/src/main/java/com/crapi/config/JwtProvider.java`
**Location:** `validateJwtToken` method (Lines 179-183)

**Issue:** The server accepts `HS256` signed tokens using the public key as the secret.

**Fix:**
Enforce `RS256` and reject `HS256` if the server is configured for RSA.

```java
    // In validateJwtToken
    // ...
    Algorithm alg = header.getAlgorithm();
    
    // Fix: Disallow HS256 if we expect RS256
    if ("HS256".equals(alg.getName())) {
        log.error("HS256 algorithm not allowed");
        return false; 
    }
    
    // Continue with RS256 verification
    RSAKey verificationKey = getKeyFromJkuHeader(header);
    // ...
```

---

## CRAPI-006: SQL Injection in Shop
**File:** `services/workshop/crapi/shop/views.py`
**Location:** `ApplyCouponView.post` (Lines 388-394)

**Issue:** Raw SQL query construction using string concatenation.

**Fix:**
Use parameterized queries provided by Django's cursor wrapper.

```python
        # services/workshop/crapi/shop/views.py
        
        with connection.cursor() as cursor:
            try:
                # Fix: Use parameters
                query = "SELECT coupon_code from applied_coupon WHERE user_id = %s AND coupon_code = %s"
                cursor.execute(query, [user.id, coupon_request_body["coupon_code"]])
                row = cursor.fetchall()
            except Exception as e:
                # ...
```

---

## CRAPI-007: BOLA in Order Details
**File:** `services/workshop/crapi/shop/views.py`
**Location:** `OrderControlView.get` (Line 122)

**Issue:** Fetches order by ID without checking if it belongs to the authenticated user.

**Fix:**
Add ownership check.

```python
    @jwt_auth_required # Ensure this decorator is present if not already
    def get(self, request, order_id=None, user=None):
        order = Order.objects.get(id=order_id)
        # Fix: Check ownership
        if order.user != user:
             return Response(
                {"message": messages.RESTRICTED}, status=status.HTTP_403_FORBIDDEN
            )
        
        # ... rest of function
```

---

## CRAPI-008: Broken Authentication (OTP Brute Force)
**File:** `services/identity/src/main/java/com/crapi/controller/AuthController.java`
**Location:** `checkOtp` method (Line 126)

**Issue:** The `/v2/check-otp` endpoint uses `otpService.validateOtp` which does not enforce a limit on attempts.

**Fix:**
Use the secure implementation or update `validateOtp` to limit attempts.

```java
  @PostMapping("/v2/check-otp")
  public ResponseEntity<CRAPIResponse> checkOtp(@RequestBody OtpForm otpForm) {
    // Fix: Use secureValidateOtp instead of validateOtp
    CRAPIResponse validateOtpResponse = otpService.secureValidateOtp(otpForm);
    
    if (validateOtpResponse.getStatus() == 200) {
       return ResponseEntity.status(HttpStatus.OK).body(validateOtpResponse);
    }
    // Handle other statuses...
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(validateOtpResponse);
  }
```

---

## CRAPI-009: SSRF in Mechanic Contact
**File:** `services/workshop/crapi/merchant/views.py`
**Location:** `ContactMechanicView.post` (Line 87)

**Issue:** Accepts arbitrary URL in `mechanic_api` parameter and makes a GET request.

**Fix:**
Validate the URL against an allowlist of trusted mechanic APIs.

```python
        # In ContactMechanicView.post
        request_url = request_data["mechanic_api"]
        
        # Fix: Validate URL
        allowed_domains = ["mechanic.example.com", "api.partner.com"] # Example allowlist
        from urllib.parse import urlparse
        domain = urlparse(request_url).netloc
        if domain not in allowed_domains:
             return Response({"message": "Invalid mechanic API URL"}, status=status.HTTP_400_BAD_REQUEST)

        # ... proceed with request
```

---

## CRAPI-010: Unauthenticated Access / BOLA in Service Requests
**File:** `services/workshop/crapi/merchant/views.py`
**Location:** `UserServiceRequestsView.get` (Line 166)

**Issue:** The endpoint lacks `@jwt_auth_required` and does not verify if the user owns the vehicle with the requested VIN.

**Fix:**
Add authentication and authorization.

```python
    @jwt_auth_required # Fix: Add decorator
    def get(self, request, vin: str, user=None): # Receive user
        # Fix: Check ownership
        vehicle = Vehicle.objects.filter(vin=vin).first()
        if not vehicle or vehicle.owner != user:
             return Response(
                {"message": messages.NO_OBJECT_FOUND},
                status=status.HTTP_404_NOT_FOUND, # Or 403
            )

        service_requests = ServiceRequest.objects.filter(vehicle__vin=vin).order_by("-created_on")
        # ...
```

---

## CRAPI-011: Unsafe LLM Database Access
**File:** `services/chatbot/src/chatbot/langgraph_agent.py`
**Location:** `SQLDatabaseToolkit` initialization (Line 52)

**Issue:** The agent uses a DB connection with likely high privileges (`postgresdb` from extensions).

**Fix:**
Ensure the database connection used by the LLM is read-only and scoped to specific tables.

```python
    # In build_langgraph_agent
    
    # Fix: Use a specific read-only connection or configure the toolkit to limit access
    # Ideally, pass a different db engine instance that connects as a read-only user
    # toolkit = SQLDatabaseToolkit(db=read_only_db, llm=llm)
    
    # Alternatively, strictly limit tools if DB separation isn't possible in code immediately
    # but strictly speaking, the DB user needs to be restricted at the database level.
```

---

## CRAPI-012: BOLA in Mechanic Reports
**File:** `services/workshop/crapi/mechanic/views.py`
**Location:** `GetReportView.get` (Line 235)

**Issue:** Returns report based on `report_id` without checking if the user is authorized (owner or mechanic).

**Fix:**
Verify user identity against the service request associated with the report.

```python
        service_request = ServiceRequest.objects.filter(id=report_id).first()
        # ... exists check ...

        # Fix: Check authorization
        if service_request.vehicle.owner != user and service_request.mechanic.user != user:
             return Response(
                {"message": messages.RESTRICTED},
                status=status.HTTP_403_FORBIDDEN,
            )
```

---

## CRAPI-013: BFLA in Video Deletion
**File:** `services/identity/src/main/java/com/crapi/controller/ProfileController.java`
**Location:** `deleteVideoBOLA` (Line 130)

**Issue:** Endpoint allows deleting videos but doesn't check if the user is an ADMIN.

**Fix:**
Add role check.

```java
  @DeleteMapping("/api/v2/admin/videos/{video_id}")
  public ResponseEntity<CRAPIResponse> deleteVideoBOLA(
      @PathVariable("video_id") Long videoId, HttpServletRequest request) {
    
    // Fix: Check for ADMIN role
    User user = userService.getUserFromToken(request);
    if (user.getRole() != Role.ADMIN) { // Assuming Role enum or similar check
         return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
      
    CRAPIResponse deleteProfileResponse = profileService.deleteAdminProfileVideo(videoId, request);
    // ...
  }
```

---

## CRAPI-014: Unsafe JWT JKU Header Trust
**File:** `services/identity/src/main/java/com/crapi/config/JwtProvider.java`
**Location:** `getKeyFromJkuHeader` (Lines 130-148)

**Issue:** Trusts arbitrary URLs in the `jku` header to fetch verification keys.

**Fix:**
Validate the JKU URL.

```java
  private RSAKey getKeyFromJkuHeader(JWSHeader header) {
      URI jku = header.getJWKURL();
      if (jku != null) {
          // Fix: Validate host
          String host = jku.getHost();
          List<String> allowedHosts = Arrays.asList("crapi.io", "auth.crapi.io"); // Trusted hosts
          if (!allowedHosts.contains(host)) {
              return null;
          }
          // ... proceed
      }
      return null;
  }
```

---

## CRAPI-015: BOLA in Video Conversion Trigger
**File:** `services/identity/src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java`
**Location:** `convertVideo` (Line 204)

**Issue:** Does not check if the `videoId` belongs to the authenticated user.

**Fix:**
Add ownership check.

```java
    // In convertVideo
    User user = userService.getUserFromToken(request);
    Optional<ProfileVideo> optionalProfileVideo = profileVideoRepository.findById(videoId);
    
    if (optionalProfileVideo.isPresent()) {
        ProfileVideo video = optionalProfileVideo.get();
        // Fix: Check ownership
        if (!video.getUser().getId().equals(user.getId())) {
             return new CRAPIResponse(UserMessage.FORBIDDEN, 403);
        }
        // ... proceed
    }
```

---

## CRAPI-016: Broken Authentication (Weak Token)
**File:** `services/identity/src/main/java/com/crapi/controller/AuthController.java`
**Location:** `loginWithTokenV2` (Line 169)

**Issue:** Allows login with a token that might be weak or predictable.

**Fix:**
Ensure the token is cryptographically strong and short-lived, or remove this mechanism if it's not needed. If kept, ensure rate limiting (which is partially addressed in OTP but maybe not here).

```java
    // Ideally remove if not secure.
    // Or ensure `userService.loginWithEmailTokenV2` validates token complexity/expiration rigorously.
```

