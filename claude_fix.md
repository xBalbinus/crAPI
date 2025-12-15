# Claude Opus 4.5 Vulnerability Fixes

This document contains remediation code for all 26 vulnerabilities identified by Claude Opus 4.5 in the crAPI codebase.

---

## VULN-001: SQL Injection in Coupon Validation

**Severity:** Critical  
**File:** `services/workshop/crapi/shop/views.py`  
**Location:** Lines 386-394 (ApplyCouponView.post)

### Vulnerable Code
```python
cursor.execute(
    "SELECT coupon_code from applied_coupon WHERE user_id = "
    + str(user.id)
    + " AND coupon_code = '"
    + coupon_request_body["coupon_code"]
    + "'"
)
```

### Fixed Code
```python
cursor.execute(
    "SELECT coupon_code FROM applied_coupon WHERE user_id = %s AND coupon_code = %s",
    [user.id, coupon_request_body["coupon_code"]]
)
```

### Explanation
Use parameterized queries instead of string concatenation. The `%s` placeholders are safely escaped by the database driver, preventing SQL injection attacks.

---

## VULN-002: NoSQL Injection in Coupon Validation

**Severity:** Critical  
**File:** `services/community/api/controllers/coupon_controller.go`  
**Location:** Lines 72-101 (ValidateCoupon)

### Vulnerable Code
```go
func ValidateCoupon(w http.ResponseWriter, r *http.Request) {
    var filter bson.M
    err := json.NewDecoder(r.Body).Decode(&filter)
    // filter is passed directly to MongoDB query
}
```

### Fixed Code
```go
func ValidateCoupon(w http.ResponseWriter, r *http.Request) {
    var request struct {
        CouponCode string `json:"coupon_code"`
    }
    err := json.NewDecoder(r.Body).Decode(&request)
    if err != nil {
        responses.ERROR(w, http.StatusBadRequest, err)
        return
    }
    
    // Validate coupon code format (alphanumeric only)
    if !regexp.MustCompile(`^[a-zA-Z0-9-]+$`).MatchString(request.CouponCode) {
        responses.ERROR(w, http.StatusBadRequest, errors.New("invalid coupon code format"))
        return
    }
    
    // Build filter with explicit field matching
    filter := bson.M{"coupon_code": request.CouponCode}
    // Continue with query...
}
```

### Explanation
Never unmarshal user input directly into a `bson.M` filter. Define a strict struct for expected fields and validate input format before querying.

---

## VULN-003: SSRF via Contact Mechanic API

**Severity:** Critical  
**File:** `services/workshop/crapi/merchant/views.py`  
**Location:** Lines 84-92 (ContactMechanicView.post)

### Vulnerable Code
```python
mechanic_api = request_body.get("mechanic_api")
response = requests.get(mechanic_api, headers=headers)
```

### Fixed Code
```python
import urllib.parse
from django.conf import settings

ALLOWED_MECHANIC_HOSTS = getattr(settings, 'ALLOWED_MECHANIC_HOSTS', ['api.crapi.internal'])

def is_url_allowed(url):
    try:
        parsed = urllib.parse.urlparse(url)
        # Block private IP ranges and localhost
        if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
            return False
        if parsed.hostname and parsed.hostname.startswith('192.168.'):
            return False
        if parsed.hostname and parsed.hostname.startswith('10.'):
            return False
        if parsed.hostname and parsed.hostname.startswith('172.'):
            return False
        # Only allow configured hosts
        return parsed.hostname in ALLOWED_MECHANIC_HOSTS
    except Exception:
        return False

# In ContactMechanicView.post:
mechanic_api = request_body.get("mechanic_api")
if not is_url_allowed(mechanic_api):
    return Response(
        {"message": "Invalid mechanic API URL"},
        status=status.HTTP_400_BAD_REQUEST
    )
response = requests.get(mechanic_api, headers=headers, timeout=5)
```

### Explanation
Implement URL allowlisting to prevent SSRF. Block private IP ranges, localhost, and only allow pre-configured trusted hosts.

---

## VULN-004: OS Command Injection in Video Conversion

**Severity:** Critical  
**File:** `services/identity/src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java`  
**Location:** Lines 236-244 (convertVideo)

### Vulnerable Code
```java
String command = "ffmpeg -i " + inputFile + " " + conversionParams + " " + outputFile;
Runtime.getRuntime().exec(command);
```

### Fixed Code
```java
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

private static final Pattern SAFE_PARAM_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-:.]+$");

public void convertVideo(String inputFile, String outputFile) {
    // Use ProcessBuilder with argument array (no shell interpretation)
    List<String> command = new ArrayList<>();
    command.add("ffmpeg");
    command.add("-i");
    command.add(inputFile);
    
    // Only use hardcoded, safe conversion parameters
    command.add("-c:v");
    command.add("libx264");
    command.add("-preset");
    command.add("medium");
    command.add("-y");
    command.add(outputFile);
    
    ProcessBuilder pb = new ProcessBuilder(command);
    pb.redirectErrorStream(true);
    Process process = pb.start();
    process.waitFor();
}
```

### Explanation
Never concatenate user input into shell commands. Use `ProcessBuilder` with an argument array to prevent shell interpretation. Remove user-controlled `conversion_params` entirely or strictly validate against an allowlist.

---

## VULN-005: JWT Algorithm Confusion

**Severity:** Critical  
**File:** `services/identity/src/main/java/com/crapi/config/JwtProvider.java`  
**Location:** Lines 179-182 (validateJwtToken)

### Vulnerable Code
```java
Jwts.parser()
    .setSigningKey(getSigningKey(token))
    .parseClaimsJws(token);
```

### Fixed Code
```java
import io.jsonwebtoken.security.SignatureAlgorithm;

private static final SignatureAlgorithm EXPECTED_ALGORITHM = SignatureAlgorithm.RS256;

public boolean validateJwtToken(String token) {
    try {
        // Parse header first to check algorithm
        String[] parts = token.split("\\.");
        String header = new String(Base64.getUrlDecoder().decode(parts[0]));
        JSONObject headerJson = new JSONObject(header);
        String algorithm = headerJson.getString("alg");
        
        // Reject tokens with unexpected algorithms
        if (!"RS256".equals(algorithm)) {
            logger.error("Rejected token with unexpected algorithm: " + algorithm);
            return false;
        }
        
        // Only use RSA public key for RS256
        Jwts.parserBuilder()
            .setSigningKey(rsaPublicKey)  // Explicitly use RSA key only
            .requireAlgorithm("RS256")
            .build()
            .parseClaimsJws(token);
        return true;
    } catch (Exception e) {
        logger.error("JWT validation failed: " + e.getMessage());
        return false;
    }
}
```

### Explanation
Explicitly enforce the expected algorithm (RS256) and reject tokens using any other algorithm. Never use the public key as an HMAC secret.

---

## VULN-006: JWT JKU Header Injection

**Severity:** Critical  
**File:** `services/identity/src/main/java/com/crapi/config/JwtProvider.java`  
**Location:** Lines 130-148 (getKeyFromJkuHeader)

### Vulnerable Code
```java
String jkuUrl = header.get("jku").toString();
// Fetches JWKS from user-controlled URL
URL url = new URL(jkuUrl);
```

### Fixed Code
```java
private static final Set<String> ALLOWED_JKU_URLS = Set.of(
    "https://identity.crapi.internal/.well-known/jwks.json",
    "https://auth.crapi.com/.well-known/jwks.json"
);

private Key getKeyFromJkuHeader(JwsHeader header) {
    String jkuUrl = header.get("jku") != null ? header.get("jku").toString() : null;
    
    // Option 1: Disable JKU entirely (recommended)
    if (jkuUrl != null) {
        logger.warn("JKU header present but disabled for security");
        throw new SecurityException("JKU header not supported");
    }
    
    // Option 2: Strict allowlist (if JKU is required)
    // if (!ALLOWED_JKU_URLS.contains(jkuUrl)) {
    //     throw new SecurityException("Untrusted JKU URL: " + jkuUrl);
    // }
    
    return getDefaultSigningKey();
}
```

### Explanation
Either disable JKU header support entirely or maintain a strict allowlist of trusted JWKS URLs. Never fetch keys from arbitrary user-controlled URLs.

---

## VULN-007: Unsigned JWT Token Accepted

**Severity:** Critical  
**File:** `services/identity/src/main/java/com/crapi/config/JwtProvider.java`  
**Location:** Lines 197-201 (validateJwtToken)

### Vulnerable Code
```java
if (jwt instanceof PlainJWT) {
    // Accepts unsigned tokens
    return extractClaims((PlainJWT) jwt);
}
```

### Fixed Code
```java
public boolean validateJwtToken(String token) {
    try {
        JWT jwt = JWTParser.parse(token);
        
        // Reject unsigned/plain JWT tokens
        if (jwt instanceof PlainJWT) {
            logger.error("Rejected unsigned JWT token");
            return false;
        }
        
        // Only accept signed JWTs
        if (!(jwt instanceof SignedJWT)) {
            logger.error("Token is not a signed JWT");
            return false;
        }
        
        SignedJWT signedJWT = (SignedJWT) jwt;
        // Continue with signature verification...
        return verifySignature(signedJWT);
    } catch (Exception e) {
        logger.error("JWT parsing failed: " + e.getMessage());
        return false;
    }
}
```

### Explanation
Always reject unsigned (PlainJWT) tokens. Only accept properly signed JWTs and verify their signatures.

---

## VULN-008: JWT KID Header Bypass

**Severity:** Critical  
**File:** `services/identity/src/main/java/com/crapi/config/JwtProvider.java`  
**Location:** Lines 158-161 (getJwtSecret)

### Vulnerable Code
```java
String kid = header.getKeyId();
if ("/dev/null".equals(kid)) {
    return "AA==";  // Hardcoded weak secret
}
```

### Fixed Code
```java
private static final Map<String, Key> VALID_KEYS = new HashMap<>();

static {
    // Load valid keys during initialization
    VALID_KEYS.put("key-1", loadKey("key-1"));
    VALID_KEYS.put("key-2", loadKey("key-2"));
}

private Key getKeyByKid(String kid) {
    if (kid == null || kid.isEmpty()) {
        throw new SecurityException("Missing key ID");
    }
    
    // Block path traversal attempts
    if (kid.contains("/") || kid.contains("\\") || kid.contains("..")) {
        logger.error("Rejected suspicious KID: " + kid);
        throw new SecurityException("Invalid key ID format");
    }
    
    Key key = VALID_KEYS.get(kid);
    if (key == null) {
        logger.error("Unknown key ID: " + kid);
        throw new SecurityException("Unknown key ID");
    }
    
    return key;
}
```

### Explanation
Validate KID against a strict allowlist of known key identifiers. Block path traversal patterns and never use hardcoded secrets.

---

## VULN-009: Log4Shell/JNDI Injection

**Severity:** Critical  
**File:** `services/identity/src/main/java/com/crapi/service/Impl/UserServiceImpl.java`  
**Location:** Lines 92-104 (authenticateUserLogin)

### Vulnerable Code
```java
if (ENABLE_LOG4J) {
    logger.info("Login attempt for user: " + email);
}
```

### Fixed Code
```java
// Option 1: Upgrade Log4j to 2.17.1+ and disable lookups
// In log4j2.xml:
// <Configuration>
//   <Properties>
//     <Property name="log4j2.formatMsgNoLookups">true</Property>
//   </Properties>
// </Configuration>

// Option 2: Sanitize input before logging
private String sanitizeForLogging(String input) {
    if (input == null) return "null";
    // Remove JNDI injection patterns
    return input.replaceAll("(?i)\\$\\{.*?}", "[REDACTED]")
                .replaceAll("(?i)jndi:", "[BLOCKED]");
}

// In authenticateUserLogin:
if (ENABLE_LOG4J) {
    logger.info("Login attempt for user: {}", sanitizeForLogging(email));
}

// Option 3 (recommended): Remove ENABLE_LOG4J flag entirely
// Use modern logging without the vulnerable feature
logger.info("Login attempt for user: {}", 
    email != null ? email.replaceAll("[^a-zA-Z0-9@._-]", "") : "unknown");
```

### Explanation
Upgrade Log4j to version 2.17.1 or later. Disable JNDI lookups via configuration. Sanitize all user input before logging.

---

## VULN-010: BOLA in Vehicle Location API

**Severity:** High  
**File:** `services/identity/src/main/java/com/crapi/controller/VehicleController.java`  
**Location:** Lines 121-128 (getLocationBOLA)

### Vulnerable Code
```java
@GetMapping("/location/{carId}")
public ResponseEntity<?> getLocationBOLA(@PathVariable UUID carId) {
    Vehicle vehicle = vehicleService.findByUUID(carId);
    return ResponseEntity.ok(vehicle.getLocation());
}
```

### Fixed Code
```java
@GetMapping("/location/{carId}")
public ResponseEntity<?> getLocation(
        @PathVariable UUID carId,
        @AuthenticationPrincipal UserDetails userDetails) {
    
    Vehicle vehicle = vehicleService.findByUUID(carId);
    if (vehicle == null) {
        return ResponseEntity.notFound().build();
    }
    
    // Verify the requesting user owns this vehicle
    User currentUser = userService.findByEmail(userDetails.getUsername());
    if (!vehicle.getOwner().getId().equals(currentUser.getId())) {
        logger.warn("Unauthorized vehicle location access attempt: user={}, vehicleId={}", 
            currentUser.getId(), carId);
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(new ErrorResponse("You don't have access to this vehicle"));
    }
    
    return ResponseEntity.ok(vehicle.getLocation());
}
```

### Explanation
Always verify that the requesting user owns the resource they're accessing. Compare the vehicle's owner ID with the authenticated user's ID.

---

## VULN-011: BOLA in Mechanic Report API

**Severity:** High  
**File:** `services/workshop/crapi/mechanic/views.py`  
**Location:** Lines 208-244 (GetReportView.get)

### Vulnerable Code
```python
def get(self, request, report_id):
    report = ServiceReport.objects.get(id=report_id)
    return Response(ReportSerializer(report).data)
```

### Fixed Code
```python
@jwt_auth_required
def get(self, request, report_id):
    user = request.user
    
    try:
        report = ServiceReport.objects.get(id=report_id)
    except ServiceReport.DoesNotExist:
        return Response(
            {"message": "Report not found"},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Check if user is the vehicle owner OR the assigned mechanic
    is_owner = report.service_request.vehicle.owner_id == user.id
    is_mechanic = report.mechanic_id == user.id
    
    if not (is_owner or is_mechanic):
        logger.warning(f"Unauthorized report access: user={user.id}, report={report_id}")
        return Response(
            {"message": "You don't have access to this report"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    return Response(ReportSerializer(report).data)
```

### Explanation
Verify that the requesting user is either the vehicle owner or the assigned mechanic before returning report data.

---

## VULN-012: Mass Assignment in Order Status

**Severity:** High  
**File:** `services/workshop/crapi/shop/views.py`  
**Location:** Lines 219-259 (OrderControlView.put)

### Vulnerable Code
```python
def put(self, request, order_id):
    order = Order.objects.get(id=order_id)
    serializer = OrderSerializer(order, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()  # Allows setting status to RETURNED
```

### Fixed Code
```python
# In serializers.py - Create a restricted serializer for updates
class OrderUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['quantity']  # Only allow updating safe fields
        # Explicitly exclude sensitive fields
        read_only_fields = ['status', 'total_price', 'user', 'created_at']

# In views.py
@jwt_auth_required
def put(self, request, order_id):
    user = request.user
    
    try:
        order = Order.objects.get(id=order_id)
    except Order.DoesNotExist:
        return Response({"message": "Order not found"}, status=404)
    
    # Verify ownership
    if order.user_id != user.id:
        return Response({"message": "Access denied"}, status=403)
    
    # Use restricted serializer
    serializer = OrderUpdateSerializer(order, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(OrderSerializer(order).data)
    
    return Response(serializer.errors, status=400)
```

### Explanation
Use a restricted serializer that only allows updating safe fields. Never allow users to modify status, price, or ownership fields directly.

---

## VULN-013: Mass Assignment in Video Properties

**Severity:** High  
**File:** `services/identity/src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java`  
**Location:** Lines 142-157 (updateProfileVideo)

### Vulnerable Code
```java
public Video updateProfileVideo(VideoForm videoForm, Video video) {
    video.setConversionParams(videoForm.getConversionParams());
    // Allows setting arbitrary conversion_params
}
```

### Fixed Code
```java
public class VideoUpdateDTO {
    private String name;
    // Only include safe, updateable fields
    // Do NOT include conversionParams
}

public Video updateProfileVideo(VideoUpdateDTO dto, Video video, User currentUser) {
    // Verify ownership
    if (!video.getUser().getId().equals(currentUser.getId())) {
        throw new ForbiddenException("You don't own this video");
    }
    
    // Only update allowed fields
    if (dto.getName() != null && !dto.getName().isEmpty()) {
        // Validate name format
        if (!dto.getName().matches("^[a-zA-Z0-9_\\- ]{1,100}$")) {
            throw new BadRequestException("Invalid video name");
        }
        video.setName(dto.getName());
    }
    
    // Never allow updating conversionParams from user input
    // conversionParams should be set internally with safe defaults
    
    return videoRepository.save(video);
}
```

### Explanation
Create a DTO that only includes safe fields. Never allow `conversionParams` to be set from user input as it leads to command injection.

---

## VULN-014: OTP Brute Force (No Rate Limit)

**Severity:** High  
**File:** `services/identity/src/main/java/com/crapi/controller/AuthController.java`  
**Location:** Lines 126-134 (checkOtp)

### Vulnerable Code
```java
@PostMapping("/v2/check-otp")
public ResponseEntity<?> checkOtp(@RequestBody OtpForm otpForm) {
    boolean valid = otpService.validateOtp(otpForm.getEmail(), otpForm.getOtp());
    // No rate limiting
}
```

### Fixed Code
```java
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import java.util.concurrent.ConcurrentHashMap;

private final ConcurrentHashMap<String, Bucket> otpAttemptBuckets = new ConcurrentHashMap<>();
private static final int MAX_OTP_ATTEMPTS = 5;
private static final int LOCKOUT_MINUTES = 15;

private Bucket getOtpBucket(String email) {
    return otpAttemptBuckets.computeIfAbsent(email, k -> {
        Bandwidth limit = Bandwidth.classic(MAX_OTP_ATTEMPTS, 
            Refill.intervally(MAX_OTP_ATTEMPTS, Duration.ofMinutes(LOCKOUT_MINUTES)));
        return Bucket.builder().addLimit(limit).build();
    });
}

@PostMapping("/v2/check-otp")
public ResponseEntity<?> checkOtp(@RequestBody OtpForm otpForm) {
    String email = otpForm.getEmail();
    
    // Check rate limit
    Bucket bucket = getOtpBucket(email);
    if (!bucket.tryConsume(1)) {
        logger.warn("OTP rate limit exceeded for: {}", email);
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
            .body(new ErrorResponse("Too many attempts. Try again in " + LOCKOUT_MINUTES + " minutes."));
    }
    
    boolean valid = otpService.validateOtp(email, otpForm.getOtp());
    
    if (!valid) {
        // Increment failure counter in OTP record
        otpService.incrementFailureCount(email);
        
        // Check if OTP should be invalidated
        if (otpService.getFailureCount(email) >= MAX_OTP_ATTEMPTS) {
            otpService.invalidateOtp(email);
            return ResponseEntity.badRequest()
                .body(new ErrorResponse("OTP invalidated due to too many failed attempts"));
        }
    }
    
    return valid ? ResponseEntity.ok().build() : ResponseEntity.badRequest().build();
}
```

### Explanation
Implement rate limiting per email address. Invalidate OTP after a maximum number of failed attempts. Use exponential backoff for repeated failures.

---

## VULN-015: BFLA in Admin Video Delete

**Severity:** High  
**File:** `services/identity/src/main/java/com/crapi/controller/ProfileController.java`  
**Location:** Lines 129-137 (deleteVideoBOLA)

### Vulnerable Code
```java
@DeleteMapping("/api/v2/admin/videos/{video_id}")
public ResponseEntity<?> deleteVideoBOLA(@PathVariable Long videoId) {
    videoService.deleteVideo(videoId);
    return ResponseEntity.ok().build();
}
```

### Fixed Code
```java
@DeleteMapping("/api/v2/admin/videos/{video_id}")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> deleteVideo(
        @PathVariable Long videoId,
        @AuthenticationPrincipal UserDetails userDetails) {
    
    // Double-check admin role programmatically
    User currentUser = userService.findByEmail(userDetails.getUsername());
    if (!currentUser.getRoles().contains(Role.ADMIN)) {
        logger.warn("Non-admin attempted admin video delete: user={}", currentUser.getId());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(new ErrorResponse("Admin access required"));
    }
    
    Video video = videoService.findById(videoId);
    if (video == null) {
        return ResponseEntity.notFound().build();
    }
    
    // Log admin action for audit
    logger.info("Admin {} deleted video {} owned by user {}", 
        currentUser.getId(), videoId, video.getUser().getId());
    
    videoService.deleteVideo(videoId);
    return ResponseEntity.ok().build();
}
```

### Explanation
Use `@PreAuthorize` annotation to enforce role-based access. Additionally verify the role programmatically and log all admin actions for audit purposes.

---

## VULN-016: JWT Signature Bypass in Dashboard

**Severity:** High  
**File:** `services/identity/src/main/java/com/crapi/service/Impl/UserServiceImpl.java`  
**Location:** Lines 201-234 (getUserByRequestToken)

### Vulnerable Code
```java
public User getUserFromTokenWithoutValidation(String token) {
    Claims claims = Jwts.parser()
        .parseClaimsJwt(token)  // Parses without verification
        .getBody();
    return userRepository.findByEmail(claims.getSubject());
}
```

### Fixed Code
```java
// Remove the unsafe method entirely
// Always use signature-verified token parsing

public User getUserFromToken(String token) {
    try {
        // Always validate signature
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
        
        String email = claims.getSubject();
        if (email == null || email.isEmpty()) {
            throw new InvalidTokenException("Token missing subject claim");
        }
        
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new UserNotFoundException("User not found for token");
        }
        
        return user;
    } catch (ExpiredJwtException e) {
        throw new InvalidTokenException("Token expired");
    } catch (JwtException e) {
        logger.error("JWT validation failed: {}", e.getMessage());
        throw new InvalidTokenException("Invalid token");
    }
}
```

### Explanation
Remove all methods that parse JWTs without signature verification. Always use `parseClaimsJws()` which requires a valid signature.

---

## VULN-017: LLM SQL Injection via Chatbot

**Severity:** High  
**File:** `services/chatbot/src/chatbot/langgraph_agent.py`  
**Location:** Lines 51-56 (build_langgraph_agent)

### Vulnerable Code
```python
from langchain_community.agent_toolkits import SQLDatabaseToolkit

toolkit = SQLDatabaseToolkit(db=db, llm=llm)
# Gives LLM full database access
```

### Fixed Code
```python
from langchain_community.utilities import SQLDatabase
from langchain.tools import Tool

# Use a read-only database connection
READONLY_DB_URI = "postgresql://readonly_user:password@localhost/crapi"

def create_safe_database_tools(llm):
    # Connect with read-only user
    db = SQLDatabase.from_uri(
        READONLY_DB_URI,
        include_tables=['products', 'public_posts'],  # Allowlist tables
        sample_rows_in_table_info=0  # Don't expose sample data
    )
    
    # Create restricted query tool
    def safe_query(query: str) -> str:
        # Block dangerous operations
        dangerous_patterns = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'ALTER', 'TRUNCATE', 
                             'GRANT', 'REVOKE', 'CREATE', '--', ';', 'UNION']
        query_upper = query.upper()
        for pattern in dangerous_patterns:
            if pattern in query_upper:
                return "Query blocked: contains restricted operation"
        
        # Only allow SELECT
        if not query_upper.strip().startswith('SELECT'):
            return "Only SELECT queries are allowed"
        
        try:
            result = db.run(query)
            # Limit response size
            return result[:1000] if len(result) > 1000 else result
        except Exception as e:
            return f"Query error: {str(e)}"
    
    return [
        Tool(
            name="database_query",
            func=safe_query,
            description="Query product catalog. Only SELECT queries on products table allowed."
        )
    ]
```

### Explanation
Use a read-only database user. Restrict accessible tables with an allowlist. Block dangerous SQL operations. Limit LLM to specific, safe queries.

---

## VULN-018: Excessive Data Exposure in Posts

**Severity:** Medium  
**File:** `services/community/api/models/post.go`  
**Location:** Lines 76-84 (Prepare Author)

### Vulnerable Code
```go
type PostResponse struct {
    Author struct {
        Email      string `json:"email"`
        VehicleID  string `json:"vehicleID"`
        PictureURL string `json:"profile_pic_url"`
    }
}
```

### Fixed Code
```go
type PublicAuthorInfo struct {
    Nickname  string `json:"nickname"`
    AvatarURL string `json:"avatar_url,omitempty"`
    // Do NOT expose email, vehicleID, or full profile URL
}

type PostResponse struct {
    ID        uint64           `json:"id"`
    Title     string           `json:"title"`
    Content   string           `json:"content"`
    Author    PublicAuthorInfo `json:"author"`
    CreatedAt time.Time        `json:"created_at"`
}

func (p *Post) PreparePublicResponse() PostResponse {
    return PostResponse{
        ID:        p.ID,
        Title:     p.Title,
        Content:   p.Content,
        Author: PublicAuthorInfo{
            Nickname:  p.Author.Nickname,
            AvatarURL: p.Author.GetPublicAvatarURL(), // Proxied URL, not direct
        },
        CreatedAt: p.CreatedAt,
    }
}
```

### Explanation
Create a dedicated public response struct that only includes necessary fields. Never expose email addresses, vehicle IDs, or other PII in public API responses.

---

## VULN-019: Unauthenticated Service Request Access

**Severity:** Medium  
**File:** `services/workshop/crapi/merchant/views.py`  
**Location:** Lines 166-200 (UserServiceRequestsView.get)

### Vulnerable Code
```python
class UserServiceRequestsView(APIView):
    def get(self, request, vin):
        # No authentication check
        requests = ServiceRequest.objects.filter(vehicle__vin=vin)
        return Response(ServiceRequestSerializer(requests, many=True).data)
```

### Fixed Code
```python
class UserServiceRequestsView(APIView):
    @jwt_auth_required
    def get(self, request, vin):
        user = request.user
        
        # Verify user owns a vehicle with this VIN
        vehicle = Vehicle.objects.filter(vin=vin, owner=user).first()
        if not vehicle:
            return Response(
                {"message": "Vehicle not found or access denied"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        service_requests = ServiceRequest.objects.filter(vehicle=vehicle)
        return Response(ServiceRequestSerializer(service_requests, many=True).data)
```

### Explanation
Add `@jwt_auth_required` decorator and verify the authenticated user owns the vehicle associated with the VIN.

---

## VULN-020: Unauthenticated Order Access

**Severity:** Medium  
**File:** `services/workshop/crapi/shop/views.py`  
**Location:** Lines 109-165 (OrderControlView.get)

### Vulnerable Code
```python
class OrderControlView(APIView):
    def get(self, request, order_id):
        # No authentication check
        order = Order.objects.get(id=order_id)
        return Response(OrderSerializer(order).data)
```

### Fixed Code
```python
class OrderControlView(APIView):
    @jwt_auth_required
    def get(self, request, order_id):
        user = request.user
        
        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return Response(
                {"message": "Order not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Verify ownership
        if order.user_id != user.id:
            logger.warning(f"Unauthorized order access: user={user.id}, order={order_id}")
            return Response(
                {"message": "Access denied"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        return Response(OrderSerializer(order).data)
```

### Explanation
Add `@jwt_auth_required` decorator and verify the authenticated user owns the order before returning data.

---

## VULN-021: Application-Layer DoS via Repeat Requests

**Severity:** Medium  
**File:** `services/workshop/crapi/merchant/views.py`  
**Location:** Lines 69-100 (ContactMechanicView repeat logic)

### Vulnerable Code
```python
number_of_repeats = request_body.get("number_of_repeats", 1)
for i in range(number_of_repeats):  # Can be up to 100
    requests.get(mechanic_api, headers=headers)
```

### Fixed Code
```python
MAX_REPEATS = 3  # Reasonable limit
REQUEST_TIMEOUT = 5  # seconds

@jwt_auth_required
@ratelimit(key='user', rate='10/m', method='POST')  # Rate limit per user
def post(self, request):
    user = request.user
    request_body = request.data
    
    # Strictly limit repeats
    number_of_repeats = min(
        int(request_body.get("number_of_repeats", 1)),
        MAX_REPEATS
    )
    
    if number_of_repeats < 1:
        number_of_repeats = 1
    
    results = []
    for i in range(number_of_repeats):
        try:
            response = requests.get(
                mechanic_api,
                headers=headers,
                timeout=REQUEST_TIMEOUT
            )
            results.append({"attempt": i+1, "status": response.status_code})
        except requests.Timeout:
            results.append({"attempt": i+1, "error": "timeout"})
            break  # Stop on timeout
        except Exception as e:
            results.append({"attempt": i+1, "error": str(e)})
            break
    
    return Response({"results": results})
```

### Explanation
Set a strict maximum for repeats (e.g., 3). Add request timeouts. Implement rate limiting per user. Stop processing on errors.

---

## VULN-022: Excessive Data in Coupon Response

**Severity:** Medium  
**File:** `services/community/api/controllers/coupon_controller.go`  
**Location:** Lines 94-101 (ValidateCoupon response)

### Vulnerable Code
```go
func ValidateCoupon(w http.ResponseWriter, r *http.Request) {
    coupon := findCoupon(code)
    responses.JSON(w, http.StatusOK, coupon)  // Returns full coupon object
}
```

### Fixed Code
```go
type CouponValidationResponse struct {
    Valid   bool   `json:"valid"`
    Message string `json:"message,omitempty"`
}

func ValidateCoupon(w http.ResponseWriter, r *http.Request) {
    var request struct {
        CouponCode string `json:"coupon_code"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        responses.JSON(w, http.StatusBadRequest, CouponValidationResponse{
            Valid:   false,
            Message: "Invalid request",
        })
        return
    }
    
    coupon, err := findCouponByCode(request.CouponCode)
    if err != nil || coupon == nil {
        responses.JSON(w, http.StatusOK, CouponValidationResponse{
            Valid:   false,
            Message: "Invalid coupon code",
        })
        return
    }
    
    // Only return validation status, not coupon details
    responses.JSON(w, http.StatusOK, CouponValidationResponse{
        Valid:   true,
        Message: "Coupon is valid",
    })
}
```

### Explanation
Only return whether the coupon is valid or not. Never expose coupon amount, creation date, or other internal details.

---

## VULN-023: Potential Path Traversal in Report Download

**Severity:** Medium  
**File:** `services/workshop/crapi/mechanic/views.py`  
**Location:** Lines 377-408 (DownloadReportView.get)

### Vulnerable Code
```python
def get(self, request, filename):
    filepath = os.path.join(REPORTS_DIR, filename)
    return FileResponse(open(filepath, 'rb'))
```

### Fixed Code
```python
import os
import re

REPORTS_DIR = "/var/app/reports"
ALLOWED_EXTENSIONS = {'.pdf', '.txt', '.csv'}

class DownloadReportView(APIView):
    @jwt_auth_required
    def get(self, request, filename):
        user = request.user
        
        # Validate filename format (alphanumeric, dash, underscore, dot only)
        if not re.match(r'^[a-zA-Z0-9_\-]+\.[a-zA-Z0-9]+$', filename):
            return Response(
                {"message": "Invalid filename format"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check extension
        _, ext = os.path.splitext(filename)
        if ext.lower() not in ALLOWED_EXTENSIONS:
            return Response(
                {"message": "File type not allowed"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Use basename to strip any path components
        safe_filename = os.path.basename(filename)
        filepath = os.path.join(REPORTS_DIR, safe_filename)
        
        # Verify the resolved path is within REPORTS_DIR
        real_path = os.path.realpath(filepath)
        if not real_path.startswith(os.path.realpath(REPORTS_DIR)):
            logger.warning(f"Path traversal attempt: user={user.id}, filename={filename}")
            return Response(
                {"message": "Access denied"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if not os.path.exists(real_path):
            return Response(
                {"message": "File not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Verify user has access to this report
        report = Report.objects.filter(filename=safe_filename, user=user).first()
        if not report:
            return Response(
                {"message": "Access denied"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        return FileResponse(open(real_path, 'rb'))
```

### Explanation
Validate filename format strictly. Use `os.path.basename()` and `os.path.realpath()` to prevent traversal. Verify the final path stays within the allowed directory.

---

## VULN-024: Overly Permissive CORS Policy

**Severity:** Low  
**File:** `services/community/api/middlewares/middlewares.go`  
**Location:** Lines 41-52 (AccessControlMiddleware)

### Vulnerable Code
```go
func AccessControlMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Credentials", "true")
    })
}
```

### Fixed Code
```go
var allowedOrigins = map[string]bool{
    "https://crapi.example.com":     true,
    "https://app.crapi.example.com": true,
    "http://localhost:3000":         true, // Development only
}

func AccessControlMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")
        
        if allowedOrigins[origin] {
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Access-Control-Allow-Credentials", "true")
            w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
            w.Header().Set("Access-Control-Max-Age", "86400")
        }
        
        // Handle preflight
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusNoContent)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}
```

### Explanation
Replace wildcard `*` with an allowlist of trusted origins. Never use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.

---

## VULN-025: TLS Certificate Validation Disabled

**Severity:** Low  
**File:** `services/community/api/auth/token.go`  
**Location:** Line 56 (ExtractTokenID)

### Vulnerable Code
```go
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    },
}
```

### Fixed Code
```go
import (
    "crypto/tls"
    "crypto/x509"
    "io/ioutil"
)

func createSecureClient() *http.Client {
    // Load CA certificate for internal services
    caCert, err := ioutil.ReadFile("/etc/ssl/certs/internal-ca.crt")
    if err != nil {
        log.Fatal("Failed to load CA certificate:", err)
    }
    
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)
    
    return &http.Client{
        Timeout: 10 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                RootCAs:            caCertPool,
                InsecureSkipVerify: false,  // Always verify
                MinVersion:         tls.VersionTLS12,
            },
        },
    }
}

// Use the secure client
var secureClient = createSecureClient()
```

### Explanation
Never disable TLS certificate verification. Use proper CA certificates for internal service communication. Set minimum TLS version to 1.2 or higher.

---

## VULN-026: Weak OTP Entropy

**Severity:** Low  
**File:** `services/identity/src/main/java/com/crapi/service/Impl/OtpServiceImpl.java`  
**Location:** Line 141 (generateOtp)

### Vulnerable Code
```java
private String generateOtp() {
    Random random = new Random();
    return String.format("%04d", random.nextInt(10000));  // 4-digit OTP
}
```

### Fixed Code
```java
import java.security.SecureRandom;

private static final SecureRandom secureRandom = new SecureRandom();
private static final int OTP_LENGTH = 6;
private static final int OTP_EXPIRY_MINUTES = 10;
private static final int MAX_ATTEMPTS = 3;

private String generateOtp() {
    // Generate 6-digit OTP using cryptographically secure random
    int otp = secureRandom.nextInt(900000) + 100000;  // 100000-999999
    return String.valueOf(otp);
}

public OtpEntity createOtp(String email) {
    // Invalidate any existing OTPs
    otpRepository.invalidateAllForEmail(email);
    
    OtpEntity otp = new OtpEntity();
    otp.setEmail(email);
    otp.setCode(generateOtp());
    otp.setExpiresAt(LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES));
    otp.setAttempts(0);
    otp.setMaxAttempts(MAX_ATTEMPTS);
    
    return otpRepository.save(otp);
}

public boolean validateOtp(String email, String code) {
    OtpEntity otp = otpRepository.findValidByEmail(email);
    
    if (otp == null) {
        return false;
    }
    
    if (otp.isExpired()) {
        otpRepository.delete(otp);
        return false;
    }
    
    if (otp.getAttempts() >= otp.getMaxAttempts()) {
        otpRepository.delete(otp);
        return false;
    }
    
    otp.setAttempts(otp.getAttempts() + 1);
    otpRepository.save(otp);
    
    if (otp.getCode().equals(code)) {
        otpRepository.delete(otp);  // Single use
        return true;
    }
    
    return false;
}
```

### Explanation
Use `SecureRandom` instead of `Random`. Increase OTP length to 6 digits (1 million combinations). Add expiration time and attempt limits. Make OTPs single-use.

---

## Summary

This document covers fixes for all 26 vulnerabilities identified by Claude Opus 4.5:

**Critical (9):**
- VULN-001 to VULN-009: SQL Injection, NoSQL Injection, SSRF, Command Injection, JWT vulnerabilities, Log4Shell

**High (8):**
- VULN-010 to VULN-017: BOLA, Mass Assignment, OTP Brute Force, BFLA, JWT Bypass, LLM Injection

**Medium (6):**
- VULN-018 to VULN-023: Data Exposure, Unauthenticated Access, DoS, Path Traversal

**Low (3):**
- VULN-024 to VULN-026: CORS, TLS, Weak OTP

Each fix follows security best practices including input validation, parameterized queries, authentication/authorization checks, rate limiting, and secure cryptographic operations.

