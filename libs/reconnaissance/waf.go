package reconnaissance

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// WAFDetector contains methods to check for WAF presence and type
type WAFDetector struct {
	url     string
	cookies string
	body    string
	headers http.Header
	statusCode int
	statusText string
}

// NewWAFDetector initializes a WAFDetector
func NewWAFDetector(url string) *WAFDetector {
	return &WAFDetector{url: url}
}

// DoRequest performs the HTTP request and sets the response details
func (w *WAFDetector) DoRequest() error {
	resp, err := http.Get(w.url)
	if err != nil {
		return fmt.Errorf("error: %v", err)
	}
	defer resp.Body.Close()

	// Read cookies
	w.cookies = resp.Header.Get("Set-Cookie")
	w.headers = resp.Header // Store headers for later use
	w.statusCode = resp.StatusCode
	w.statusText = resp.Status // e.g. "200 OK"

	// Read response body and handle errors
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading body: %v", err)
	}

	w.body = string(bodyBytes)

	return nil
}

// isWAF checks for the presence of WAF and identifies its type
func (w *WAFDetector) IsWAF() (bool, string) {
	if w.checkSchema01() {
		return true, "Generic WAF (rejection messages detected)."
	}

	if w.isAeSecureWAF() {
		return true, "aeSecure WAF detected."
	}
	
	if w.isAireeWAF() {
		return true, "AireeCDN (Airee) WAF detected."
	}
	
	if w.isAirlockWAF() {
		return true, "Airlock (Phion/Ergon) WAF detected."
	}
	
	if w.isAlertLogicWAF() {
		return true, "Alert Logic (Alert Logic) WAF detected."
	}
	
	if w.isAliYunDunWAF() {
		return true, "AliYunDun (Alibaba Cloud Computing) WAF detected."
	}
	
	if w.isAnquanbaoWAF() {
		return true, "Anquanbao WAF detected."
	}
	
	if w.isAnYuWAF() {
		return true, "AnYu (AnYu Technologies) WAF detected."
	}
	
	if w.isAzureAppGwWAF() {
		return true, "Azure Application Gateway (Microsoft) WAF detected."
	}
	
	if w.isApproachWAF() {
		return true, "Approach WAF detected."
	}
	
	if w.isArvanCloudWAF() {
		return true, "ArvanCloud WAF detected."
	}
	
	if w.isASPAWAF() {
		return true, "ASPA Firewall (ASPA Engineering Co.) WAF detected."
	}
	
	if w.isAspNetGenericWAF() {
		return true, "ASP.NET Generic (Microsoft) WAF detected."
	}
	
	if w.isAstraWAF() {
		return true, "Astra (Czar Securities) WAF detected."
	}
	
	if w.isAwsElbWAF() {
		return true, "AWS Elastic Load Balancer (Amazon) WAF detected."
	}
	
	if w.isAzionEdgeFirewallWAF() {
		return true, "Azion Edge Firewall (Azion) WAF detected."
	}
	
	if w.isBaffinBayWAF() {
		return true, "Baffin Bay (Mastercard) WAF detected."
	}
	
	if w.isYunjiasuWAF() {
		return true, "Yunjiasu (Baidu Cloud Computing) WAF detected."
	}
	
	if w.isBarikodeWAF() {
		return true, "Barikode (Ethic Ninja) WAF detected."
	}
	
	if w.isBarracudaWAF() {
		return true, "Barracuda (Barracuda Networks) WAF detected."
	}
	
	if w.isBekchyWAF() {
		return true, "Bekchy (Faydata Technologies Inc.) WAF detected."
	}
	
	if w.isBelugaWAF() {
		return true, "Beluga CDN (Beluga) WAF detected."
	}
	
	if w.isBinarySecWAF() {
		return true, "BinarySec (BinarySec) WAF detected."
	}
	
	if w.isBitNinjaWAF() {
		return true, "BitNinja (BitNinja) WAF detected."
	}
	
	if w.isBlockDoSWAF() {
		return true, "BlockDoS (BlockDoS) WAF detected."
	}
	
	if w.isBluedonWAF() {
		return true, "Bluedon (Bluedon IST) WAF detected."
	}
	
	if w.isBulletProofSecurityProWAF() {
		return true, "BulletProof Security Pro (AITpro Security) WAF detected."
	}
	
	if w.isCacheFlyWAF() {
		return true, "CacheFly CDN (CacheFly) WAF detected."
	}
	
	if w.isCacheWallWAF() {
		return true, "CacheWall (Varnish) WAF detected."
	}
	
	if w.isCdnNSAppGwWAF() {
		return true, "CdnNS Application Gateway (CdnNs/WdidcNet) WAF detected."
	}
	
	if w.isWpCerberWAF() {
		return true, "WP Cerber Security (Cerber Tech) WAF detected."
	}
	
	if w.isChinaCacheLbWAF() {
		return true, "ChinaCache Load Balancer (ChinaCache) WAF detected."
	}
	
	if w.isChuangYuShieldWAF() {
		return true, "Chuang Yu Shield (Yunaq) WAF detected."
	}
	
	if w.isAceXmlGatewayWAF() {
		return true, "ACE XML Gateway (Cisco) WAF detected."
	}
	
	if w.isCloudbricWAF() {
		return true, "Cloudbric (Penta Security) WAF detected."
	}
	
	if w.isCloudflareWAF() {
		return true, "Cloudflare WAF detected."
	}
	
	if w.isCloudFrontWAF() {
		return true, "CloudFront (Amazon) WAF detected."
	}
	
	if w.isCloudProtectorWAF() {
		return true, "Cloud Protector (Rohde & Schwarz CyberSecurity) WAF detected."
	}
	
	if w.isComodoCWatchWAF() {
		return true, "Comodo cWatch (Comodo CyberSecurity) WAF detected."
	}
	
	if w.isCrawlProtectWAF() {
		return true, "CrawlProtect (Jean-Denis Brun) WAF detected."
	}
	
	if w.isDDoSGuardWAF() {
		return true, "DDoS-GUARD (DDOS-GUARD CORP.) WAF detected."
	}
	
	if w.isDenyALLWAF() {
		return true, "DenyALL (Rohde & Schwarz CyberSecurity) WAF detected."
	}
	
	if w.isDistilWAF() {
		return true, "Distil (Distil Networks) WAF detected."
	}
	
	if w.isDOSarrestWAF() {
		return true, "DOSarrest (DOSarrest Internet Security) WAF detected."
	}
	
	if w.isDotDefenderWAF() {
		return true, "DotDefender (Applicure Technologies) WAF detected."
	}
	
	if w.isDynamicWebInjCheckWAF() {
		return true, "DynamicWeb Injection Check (DynamicWeb) WAF detected."
	}
	
	if w.isEdgecastWAF() {
		return true, "Edgecast (Verizon Digital Media) WAF detected."
	}
	
	if w.isEisooCloudFirewallWAF() {
		return true, "Eisoo Cloud Firewall (Eisoo) WAF detected."
	}
	
	if w.isEnvoyWAF() {
		return true, "Envoy (EnvoyProxy) WAF detected."
	}
	
	if w.isExpressionEngineWAF() {
		return true, "Expression Engine (EllisLab) WAF detected."
	}
	
	if w.isBigIpApManagerWAF() {
		return true, "BIG-IP AP Manager (F5 Networks) WAF detected."
	}
	
	if ok, msg := w.isF5BigIPAppSec(); ok {
		return true, msg
	}
	
	if w.isBigIpLTMWAF() {
		return true, "BIG-IP Local Traffic Manager (F5 Networks) WAF detected."
	}
	
	if w.isFirePassWAF() {
		return true, "FirePass (F5 Networks) WAF detected."
	}
	
	if w.isTrafficShieldWAF() {
		return true, "TrafficShield (F5 Networks) WAF detected."
	}
	
	if w.isFastlyWAF() {
		return true, "Fastly (Fastly CDN) WAF detected."
	}
	
	if w.isFortiGateWAF() {
		return true, "FortiGate (Fortinet) WAF detected."
	}
	
	if w.isFortiGuardWAF() {
		return true, "FortiGuard (Fortinet) WAF detected."
	}
	
	if w.isFortiWebWAF() {
		return true, "FortiWeb (Fortinet) WAF detected."
	}
	
	if w.isAzureFrontDoorWAF() {
		return true, "Azure Front Door (Microsoft) WAF detected."
	}
	
	if w.isGcloudArmorWAF() {
		return true, "Google Cloud Armor (Google Cloud) WAF detected."
	}
	
	if w.isGoDaddyWAF() {
		return true, "GoDaddy Website Protection (GoDaddy) WAF detected."
	}
	
	if w.isGreywizardWAF() {
		return true, "Greywizard (Grey Wizard) WAF detected."
	}
	
	if w.isHuaweiCloudWAF() {
		return true, "Huawei Cloud Firewall (Huawei) WAF detected."
	}
	
	if w.isHyperGuardWAF() {
		return true, "HyperGuard (Art of Defense) WAF detected."
	}
	
	if w.isDataPowerWAF() {
		return true, "DataPower (IBM) WAF detected."
	}
	
	if w.isImunify360WAF() {
		return true, "Imunify360 (CloudLinux) WAF detected."
	}
	
	if w.isIncapsulaWAF() {
		return true, "Incapsula (Imperva Inc.) WAF detected."
	}
	
	if w.isIndusGuardWAF() {
		return true, "IndusGuard (Indusface) WAF detected."
	}
	
	if w.isInstartDXWAF() {
		return true, "Instart DX (Instart Logic) WAF detected."
	}
	
	if w.isISAserverWAF() {
		return true, "ISA Server (Microsoft) WAF detected."
	}
	
	if w.isJanusecWAF() {
		return true, "Janusec Application Gateway (Janusec) WAF detected."
	}
	
	if w.isJiasuleWAF() {
		return true, "Jiasule (Jiasule) WAF detected."
	}
	
	if w.isKempLoadMasterWAF() {
		return true, "Kemp LoadMaster (Progress Software) WAF detected."
	}
	
	if w.isKeyCDNWAF() {
		return true, "KeyCDN (KeyCDN) WAF detected."
	}
	
	if w.isKsWAF() {
		return true, "KS-WAF (KnownSec) WAF detected."
	}
	
	if w.isKonaSiteDefenderWAF() {
		return true, "Kona SiteDefender (Akamai) WAF detected."
	}
	
	if w.isLimeLightCDNWAF() {
		return true, "LimeLight CDN (LimeLight) WAF detected."
	}
	
	if w.isLink11WAAPWAF() {
		return true, "Link11 WAAP (Link11) WAF detected."
	}
	
	if w.isLiteSpeedWAF() {
		return true, "LiteSpeed (LiteSpeed Technologies) WAF detected."
	}
	
	if w.isMalcareWAF() {
		return true, "Malcare (Inactiv) WAF detected."
	}
	
	if w.isMaxCDNWAF() {
		return true, "MaxCDN (MaxCDN) WAF detected."
	}
	
	if w.isMissionControlShieldWAF() {
		return true, "Mission Control Shield (Mission Control) WAF detected."
	}
	
	if w.isModSecurityWAF() {
		return true, "ModSecurity (SpiderLabs) WAF detected."
	}
	
	if w.isNaxsiWAF() {
		return true, "NAXSI (NBS Systems) WAF detected."
	}
	
	if w.isNemesidaWAF() {
		return true, "Nemesida (PentestIt) WAF detected."
	}
	
	if w.isNetContinuumWAF() {
		return true, "NetContinuum (Barracuda Networks) WAF detected."
	}
	
	if w.isNetScalerAppFirewallWAF() {
		return true, "NetScaler AppFirewall (Citrix Systems) WAF detected."
	}
	
	if w.isNevisProxyWAF() {
		return true, "NevisProxy (AdNovum) WAF detected."
	}
	
	if w.isNewdefendWAF() {
		return true, "Newdefend (NewDefend) WAF detected."
	}
	
	if w.isNexusGuardFirewallWAF() {
		return true, "NexusGuard Firewall (NexusGuard) WAF detected."
	}
	
	if w.isNinjaFirewallWAF() {
		return true, "NinjaFirewall (NinTechNet) WAF detected."
	}
	
	if w.isNSFocusWAF() {
		return true, "NSFocus (NSFocus Global Inc.) WAF detected."
	}
	
	if w.isNullDDoSProtectionWAF() {
		return true, "NullDDoS Protection (NullDDoS) WAF detected."
	}
	
	if w.isOnMessageShieldWAF() {
		return true, "OnMessage Shield (BlackBaud) WAF detected."
	}
	
	if w.isOpenRestyLuaNginxWAF() {
		return true, "Open-Resty Lua Nginx (FLOSS) WAF detected."
	}
	
	if w.isOracleCloudWAF() {
		return true, "Oracle Cloud (Oracle) WAF detected."
	}
	
	if w.isPaloAltoNextGenFirewallWAF() {
		return true, "Palo Alto Next Gen Firewall (Palo Alto Networks) WAF detected."
	}
	
	if w.is360PanYunWAF() {
		return true, "360PanYun (360 Technologies) WAF detected."
	}
	
	if w.isPentaWAFWAF() {
		return true, "PentaWAF (Global Network Services) WAF detected."
	}
	
	if w.isPerimeterXWAF() {
		return true, "PerimeterX (PerimeterX) WAF detected."
	}
	
	if w.isPkSecurityIDS() {
		return true, "pkSecurity IDS (pkSec) WAF detected."
	}
	
	if w.isPowerCDNWAF() {
		return true, "PowerCDN (PowerCDN) WAF detected."
	}
	
	if w.isProfenseWAF() {
		return true, "Profense (ArmorLogic) WAF detected."
	}
	
	if w.isPTApplicationFirewallWAF() {
		return true, "PT Application Firewall (Positive Technologies) WAF detected."
	}
	
	if w.isPuhuiWAF() {
		return true, "Puhui (Puhui) WAF detected."
	}
	
	if w.isQcloudWAF() {
		return true, "Qcloud (Tencent Cloud) WAF detected."
	}
	
	if w.isQiniuWAF() {
		return true, "Qiniu (Qiniu CDN) WAF detected."
	}
	
	if w.isQratorWAF() {
		return true, "Qrator (Qrator) WAF detected."
	}
	
	if w.isAppWallWAF() {
		return true, "AppWall (Radware) WAF detected."
	}
	
	if w.isReblazeWAF() {
		return true, "Reblaze (Reblaze) WAF detected."
	}

	if w.isReflectedNetworksWAF() {
		return true, "Reflected Networks (Reflected Networks) WAF detected."
	}
	
	if w.isRSFirewallWAF() {
		return true, "RSFirewall (RSJoomla!) WAF detected."
	}
	
	if w.isRequestValidationModeWAF() {
		return true, "RequestValidationMode (Microsoft) WAF detected."
	}
	
	if w.isSabreFirewallWAF() {
		return true, "Sabre Firewall (Sabre) WAF detected."
	}
	
	if w.isSafe3WebFirewallWAF() {
		return true, "Safe3 Web Firewall (Safe3) WAF detected."
	}
	
	if w.isSafedogWAF() {
		return true, "Safedog (SafeDog) WAF detected."
	}
	
	if w.isSafelineWAF() {
		return true, "Safeline (Chaitin Tech.) WAF detected."
	}
	
	if w.isSecKingWAF() {
		return true, "SecKing (SecKing) WAF detected."
	}
	
	if w.isSecuPressWPSecurityWAF() {
		return true, "SecuPress WP Security (SecuPress) WAF detected."
	}
	
	if w.isSecureEntryWAF() {
		return true, "Secure Entry (United Security Providers) WAF detected."
	}
	
	if w.isEeyeSecureIISWAF() {
		return true, "eEye SecureIIS (BeyondTrust) WAF detected."
	}
	
	if w.isSecureSphereWAF() {
		return true, "SecureSphere (Imperva Inc.) WAF detected."
	}
	
	if w.isSENginxWAF() {
		return true, "SEnginx (Neusoft) WAF detected."
	}
	
	if w.isServerDefenderVPWAF() {
		return true, "ServerDefender VP (Port80 Software) WAF detected."
	}
	
	if w.isShadowDaemonWAF() {
		return true, "Shadow Daemon (Zecure) WAF detected."
	}
	
	if w.isShieldonFirewallWAF() {
		return true, "Shieldon Firewall (Shieldon.io) WAF detected."
	}
	
	if w.isShieldSecurityWAF() {
		return true, "Shield Security (One Dollar Plugin) WAF detected."
	}
	
	if w.isSiteGroundWAF() {
		return true, "SiteGround (SiteGround) WAF detected."
	}
	
	if w.isSiteGuardWAF() {
		return true, "SiteGuard (EG Secure Solutions Inc.) WAF detected."
	}
	
	if w.isSitelockWAF() {
		return true, "Sitelock (TrueShield) WAF detected."
	}
	
	if w.isSonicWallWAF() {
		return true, "SonicWall (Dell) WAF detected."
	}
	
	if w.isUTMWebProtectionWAF() {
		return true, "UTM Web Protection (Sophos) WAF detected."
	}
	
	if w.isSquarespaceWAF() {
		return true, "Squarespace (Squarespace) WAF detected."
	}
	
	if w.isSquidProxyIDS() {
		return true, "SquidProxy IDS (SquidProxy) WAF detected."
	}
	
	if w.isStackPathWAF() {
		return true, "StackPath (StackPath) WAF detected."
	}
	
	if w.isSucuriCloudProxyWAF() {
		return true, "Sucuri CloudProxy (Sucuri Inc.) WAF detected."
	}

	if w.isTencentCloudWAF() {
		return true, "Tencent Cloud Firewall (Tencent Technologies) WAF detected."
	}
	
	if w.isTerosWAF() {
		return true, "Teros (Citrix Systems) WAF detected."
	}
	
	if w.isThreatXWAF() {
		return true, "ThreatX (A10 Networks) WAF detected."
	}
	
	if w.isTransIPWebFirewallWAF() {
		return true, "TransIP Web Firewall (TransIP) WAF detected."
	}
	
	if w.isUEWafWAF() {
		return true, "UEWaf (UCloud) WAF detected."
	}
	
	if w.isURLMasterSecurityCheckWAF() {
		return true, "URLMaster SecurityCheck (iFinity/DotNetNuke) WAF detected."
	}
	
	if w.isURLScanWAF() {
		return true, "URLScan (Microsoft) WAF detected."
	}
	
	if w.isVaritiWAF() {
		return true, "Variti (Variti) WAF detected."
	}
	
	if w.isVarnishOWASPWAF() {
		return true, "Varnish (OWASP) WAF detected."
	}

	if w.isVercelWAF() {
		return true, "Vercel WAF (Vercel) WAF detected."
	}
	
	if w.isViettelWAF() {
		return true, "Viettel (Cloudrity) WAF detected."
	}
	
	if w.isVirusDieWAF() {
		return true, "VirusDie (VirusDie LLC) WAF detected."
	}
	
	if w.isWallarmWAF() {
		return true, "Wallarm (Wallarm Inc.) WAF detected."
	}
	
	if w.isWatchGuardWAF() {
		return true, "WatchGuard (WatchGuard Technologies) WAF detected."
	}
	
	if w.isWebARXWAF() {
		return true, "WebARX (WebARX Security Solutions) WAF detected."
	}
	
	if w.isWebKnightWAF() {
		return true, "WebKnight (AQTRONIX) WAF detected."
	}
	
	if w.isWebLandWAF() {
		return true, "WebLand (WebLand) WAF detected."
	}
	
	if w.isRayWAF() {
		return true, "RayWAF (WebRay Solutions) WAF detected."
	}
	
	if w.isWebSEALWAF() {
		return true, "WebSEAL (IBM) WAF detected."
	}
	
	if w.isWebTotemWAF() {
		return true, "WebTotem (WebTotem) WAF detected."
	}
	
	if w.isWest263CDNWAF() {
		return true, "West263 CDN (West263CDN) WAF detected."
	}
	
	if w.isWordfenceWAF() {
		return true, "Wordfence (Defiant) WAF detected."
	}
	
	if w.isWpmudevWAF() {
		return true, "wpmudev WAF (Incsub) WAF detected."
	}
	
	if w.isWTSWAF() {
		return true, "WTS-WAF (WTS) WAF detected."
	}
	
	if w.is360WangZhanBaoWAF() {
		return true, "360WangZhanBao (360 Technologies) WAF detected."
	}
	
	if w.isXLabsSecurityWAF() {
		return true, "XLabs Security WAF (XLabs) WAF detected."
	}

	if w.isXuanwudunWAF() {
		return true, "Xuanwudun (Xuanwudun) WAF detected."
	}
	
	if w.isYundunWAF() {
		return true, "Yundun (Yundun) WAF detected."
	}
	
	if w.isYunsuoWAF() {
		return true, "Yunsuo (Yunsuo) WAF detected."
	}
	
	if w.isYXLinkWAF() {
		return true, "YXLink (YxLink Technologies) WAF detected."
	}
	
	if w.isZenedgeWAF() {
		return true, "Zenedge (Zenedge) WAF detected."
	}
	
	if w.isZScalerWAF() {
		return true, "ZScaler (Accenture) WAF detected."
	}

	return false, ""
}

// checkSchema01 checks for specific strings in the response body
func (w *WAFDetector) checkSchema01() bool {
	return w.matchContent("the requested url was rejected") &&
		w.matchContent("please consult with your administrator")
}

// isAeSecureWAF checks for aeSecure-specific headers and content
func (w *WAFDetector) isAeSecureWAF() bool {
	if w.matchHeader("aeSecure-code", `.+?`) {
		return true
	}

	if w.matchContent(`aesecure_denied\.png`) {
		return true
	}

	return false
}

// isAireeWAF implements the AireeCDN (Airee) checks
func (w *WAFDetector) isAireeWAF() bool {
	if w.matchHeader("Server", "Airee") {
		return true
	}
	if w.matchHeader("X-Cache", `(\w+\.)?airee\.cloud`) {
		return true
	}
	if w.matchContent(`airee\.cloud`) {
		return true
	}
	return false
}

// isAirlockWAF checks for Airlock (Phion/Ergon)
func (w *WAFDetector) isAirlockWAF() bool {
	if w.matchCookie(`^al[_-]?(sess|lb)=`) {
		return true
	}
	if w.matchContent(`server detected a syntax error in your request`) {
		return true
	}
	return false
}

// isAlertLogicWAF checks for Alert Logic WAF
func (w *WAFDetector) isAlertLogicWAF() bool {
	return w.matchContent(`<(title|h\d{1})>requested url cannot be found`) &&
		w.matchContent(`we are sorry.{0,10}?but the page you are looking for cannot be found`) &&
		w.matchContent(`back to previous page`) &&
		w.matchContent(`proceed to homepage`) &&
		w.matchContent(`reference id`)
}

// isAliYunDunWAF checks for AliYunDun (Alibaba Cloud Computing)
func (w *WAFDetector) isAliYunDunWAF() bool {
	return w.matchContent(`error(s)?\.aliyun(dun)?\.(com|net)?`) &&
		w.matchContent(`alicdn\.com\/sd\-base\/static\/\d{1,2}\.\d{1,2}\.\d{1,2}\/image\/405\.png`) &&
		w.matchContent(`Sorry, your request has been blocked as it may cause potential threats to the server's security\.`) &&
		w.statusCode == 405
}

// isAnquanbaoWAF checks for Anquanbao
func (w *WAFDetector) isAnquanbaoWAF() bool {
	return w.matchHeader("X-Powered-By-Anquanbao", ".+?") ||
		w.matchContent(`aqb_cc/error/`)
}

// isAnYuWAF checks for AnYu Technologies
func (w *WAFDetector) isAnYuWAF() bool {
	return w.matchContent(`anyu.{0,10}?the green channel`) ||
		w.matchContent(`your access has been intercepted by anyu`)
}

// isAzureAppGwWAF checks for Azure Application Gateway (Microsoft)
func (w *WAFDetector) isAzureAppGwWAF() bool {
	return w.matchContent(`<center>Microsoft-Azure-Application-Gateway/v2</center>`) &&
		w.matchContent(`<h1>403 Forbidden</h1>`)
}

// isApproachWAF checks for Approach
func (w *WAFDetector) isApproachWAF() bool {
	return w.matchContent(`approach.{0,10}?web application (firewall|filtering)`) ||
		w.matchContent(`approach.{0,10}?infrastructure team`)
}

// isArvanCloudWAF checks for ArvanCloud
func (w *WAFDetector) isArvanCloudWAF() bool {
	return w.matchHeader("Server", "ArvanCloud")
}

// isASPAWAF checks for ASPA Firewall (ASPA Engineering Co.)
func (w *WAFDetector) isASPAWAF() bool {
	return w.matchHeader("Server", `ASPA[\-_]?WAF`) ||
		w.matchHeader("ASPA-Cache-Status", `.+?`)
}

// isAspNetGenericWAF checks for ASP.NET Generic (Microsoft)
func (w *WAFDetector) isAspNetGenericWAF() bool {
	return w.matchContent(`iis (\d+\.)+?detailed error`) ||
		w.matchContent(`potentially dangerous request querystring`) ||
		w.matchContent(`application error from being viewed remotely (for security reasons)?`) ||
		w.matchContent(`An application error occurred on the server`)
}

// isAstraWAF checks for Astra (Czar Securities)
func (w *WAFDetector) isAstraWAF() bool {
	return w.matchCookie(`^cz_astra_csrf_cookie`) ||
		w.matchContent(`astrawebsecurity\.freshdesk\.com`) ||
		w.matchContent(`www\.getastra\.com/assets/images`)
}

// isAwsElbWAF checks for AWS Elastic Load Balancer (Amazon)
func (w *WAFDetector) isAwsElbWAF() bool {
	return w.matchHeader("X-AMZ-ID", ".+?") ||
		w.matchHeader("X-AMZ-Request-ID", ".+?") ||
		w.matchCookie(`^aws.?alb=`) ||
		w.matchHeader("Server", `aws.?elb`) ||
		w.matchHeader("X-Blocked-By-WAF", `Blocked_by_custom_response_for_AWSManagedRules.*`)
}

// isAzionEdgeFirewallWAF checks for Azion Edge Firewall (Azion)
func (w *WAFDetector) isAzionEdgeFirewallWAF() bool {
	return w.matchHeader("x-azion-edge-pop", `.+?`) ||
		w.matchHeader("x-azion-request-id", `.+?`)
}

// isBaffinBayWAF checks for Baffin Bay (Mastercard)
func (w *WAFDetector) isBaffinBayWAF() bool {
	return w.matchHeader("server", "baffin-bay-inlet")
}

// isYunjiasuWAF checks for Yunjiasu (Baidu Cloud Computing)
func (w *WAFDetector) isYunjiasuWAF() bool {
	return w.matchHeader("Server", `yunjiasu.*`) ||
		w.matchContent(`href="/.well-known/yunjiasu-cgi/"`) ||
		w.matchContent(`document.cookie='yjs_use_ob=0`)
}

// isBarikodeWAF checks for Barikode (Ethic Ninja)
func (w *WAFDetector) isBarikodeWAF() bool {
	return w.matchContent(`<strong>barikode<.strong>`)
}

// isBarracudaWAF checks for Barracuda Networks WAF
func (w *WAFDetector) isBarracudaWAF() bool {
	return w.matchCookie(`^barra_counter_session=`) ||
		w.matchCookie(`^BNI__BARRACUDA_LB_COOKIE=`) ||
		w.matchCookie(`^BNI_persistence=`) ||
		w.matchCookie(`^BN[IE]S_.*?=`) ||
		w.matchContent(`Barracuda.Networks`)
}

// isBekchyWAF checks for Bekchy (Faydata Technologies Inc.)
func (w *WAFDetector) isBekchyWAF() bool {
	return w.matchContent(`Bekchy.{0,10}?Access Denied`) ||
		w.matchContent(`bekchy\.com/report`)
}

// isBelugaWAF checks for Beluga CDN (Beluga)
func (w *WAFDetector) isBelugaWAF() bool {
	return w.matchHeader("Server", `Beluga`) ||
		w.matchCookie(`^beluga_request_trail=`)
}

// isBinarySecWAF checks for BinarySec
func (w *WAFDetector) isBinarySecWAF() bool {
	return w.matchHeader("Server", "BinarySec") ||
		w.matchHeader("x-binarysec-via", ".+") ||
		w.matchHeader("x-binarysec-nocache", ".+")
}

// isBitNinjaWAF checks for BitNinja
func (w *WAFDetector) isBitNinjaWAF() bool {
	return w.matchContent(`Security check by BitNinja`) ||
		w.matchContent(`Visitor anti-robot validation`)
}

// isBlockDoSWAF checks for BlockDoS
func (w *WAFDetector) isBlockDoSWAF() bool {
	return w.matchHeader("Server", `blockdos\.net`)
}

// isBluedonWAF checks for Bluedon (Bluedon IST)
func (w *WAFDetector) isBluedonWAF() bool {
	return w.matchHeader("Server", `BDWAF`) ||
		w.matchContent(`bluedon web application firewall`)
}

// isBulletProofSecurityProWAF checks for BulletProof Security Pro (AITpro Security)
func (w *WAFDetector) isBulletProofSecurityProWAF() bool {
	return w.matchContent(`\+?bpsMessage`) &&
		w.matchContent(`403 Forbidden Error Page`) &&
		w.matchContent(`If you arrived here due to a search`)
}

// isCacheFlyWAF checks for CacheFly CDN (CacheFly)
func (w *WAFDetector) isCacheFlyWAF() bool {
	return w.matchHeader("BestCDN", `Cachefly`) ||
		w.matchCookie(`^cfly_req.*=`)
}

// isCacheWallWAF checks for CacheWall (Varnish)
func (w *WAFDetector) isCacheWallWAF() bool {
	return w.matchHeader("Server", "Varnish") ||
		w.matchHeader("X-Varnish", ".+") ||
		w.matchHeader("X-Cachewall-Action", ".+?") ||
		w.matchHeader("X-Cachewall-Reason", ".+?") ||
		w.matchContent(`security by cachewall`) ||
		w.matchContent(`403 naughty.{0,10}?not nice!`) ||
		w.matchContent(`varnish cache server`)
}

// isCdnNSAppGwWAF checks for CdnNS Application Gateway (CdnNs/WdidcNet)
func (w *WAFDetector) isCdnNSAppGwWAF() bool {
	return w.matchContent(`cdnnswaf application gateway`)
}

// isWpCerberWAF checks for WP Cerber Security (Cerber Tech)
func (w *WAFDetector) isWpCerberWAF() bool {
	return w.matchContent(`your request looks suspicious or similar to automated`) &&
		w.matchContent(`our server stopped processing your request`) &&
		w.matchContent(`We.re sorry.{0,10}?you are not allowed to proceed`) &&
		w.matchContent(`requests from spam posting software`) &&
		w.matchContent(`<title>403 Access Forbidden`)
}

// isChinaCacheLbWAF checks for ChinaCache Load Balancer (ChinaCache)
func (w *WAFDetector) isChinaCacheLbWAF() bool {
	return w.matchHeader("Powered-By-ChinaCache", ".+")
}

// isChuangYuShieldWAF checks for Chuang Yu Shield (Yunaq)
func (w *WAFDetector) isChuangYuShieldWAF() bool {
	return w.matchContent(`www\.365cyd\.com`) ||
		w.matchContent(`help\.365cyd\.com/cyd\-error\-help\.html\?code=403`)
}

// isAceXmlGatewayWAF checks for ACE XML Gateway (Cisco)
func (w *WAFDetector) isAceXmlGatewayWAF() bool {
	return w.matchHeader("Server", "ACE XML Gateway")
}

// isCloudbricWAF checks for Cloudbric (Penta Security)
func (w *WAFDetector) isCloudbricWAF() bool {
	return w.matchContent(`<title>Cloudbric.{0,5}?ERROR!`) ||
		w.matchContent(`Your request was blocked by Cloudbric`) ||
		w.matchContent(`please contact Cloudbric Support`) ||
		w.matchContent(`cloudbric\.zendesk\.com`) ||
		w.matchContent(`Cloudbric Help Center`) ||
		w.matchContent(`malformed request syntax.{0,4}?invalid request message framing.{0,4}?or deceptive request routing`)
}

// isCloudflareWAF checks for Cloudflare-specific headers and cookies
func (w *WAFDetector) isCloudflareWAF() bool {
	if w.matchHeader("Server", "cloudflare") {
		return true
	}

	if w.matchHeader("Server", `cloudflare[-_]nginx`) {
		return true
	}

	if w.matchHeader("cf-ray", `.+?`) {
		return true
	}

	if w.matchCookie(`__cfduid`) {
		return true
	}

	return false
}

// isCloudFrontWAF checks for CloudFront (Amazon)
func (w *WAFDetector) isCloudFrontWAF() bool {
	return w.matchHeader("Server", "Cloudfront") ||
		w.matchHeader("Via", `([0-9\.]+?)? \w+?\.cloudfront\.net \(Cloudfront\)`) ||
		w.matchHeader("X-Amz-Cf-Id", ".+?") ||
		w.matchHeader("X-Cache", "Error from Cloudfront") ||
		w.matchContent(`Generated by cloudfront \(CloudFront\)`)
}

// isCloudProtectorWAF checks for Cloud Protector (Rohde & Schwarz CyberSecurity)
func (w *WAFDetector) isCloudProtectorWAF() bool {
	return w.matchContent(`Cloud Protector.*?by Rohde.{3,8}?Schwarz Cybersecurity`) ||
		w.matchContent(`<a href='https?:\/\/(?:www\.)?cloudprotector\.com\/'>R.{1,6}?S.Cloud Protector`)
}

// isComodoCWatchWAF checks for Comodo cWatch (Comodo CyberSecurity)
func (w *WAFDetector) isComodoCWatchWAF() bool {
	return w.matchHeader("Server", `Protected by COMODO WAF(.+)?`)
}

// isCrawlProtectWAF checks for CrawlProtect (Jean-Denis Brun)
func (w *WAFDetector) isCrawlProtectWAF() bool {
	return w.matchCookie(`^crawlprotecttag=`) ||
		w.matchContent(`<title>crawlprotect`) ||
		w.matchContent(`this site is protected by crawlprotect`)
}

// isDDoSGuardWAF checks for DDoS-GUARD (DDOS-GUARD CORP.)
func (w *WAFDetector) isDDoSGuardWAF() bool {
	return w.matchCookie(`^__ddg1.*?=`) ||
		w.matchCookie(`^__ddg2.*?=`) ||
		w.matchCookie(`^__ddgid.*?=`) ||
		w.matchCookie(`^__ddgmark.*?=`) ||
		w.matchHeader("Server", "ddos-guard")
}

// isDenyALLWAF checks for DenyALL (Rohde & Schwarz CyberSecurity)
func (w *WAFDetector) isDenyALLWAF() bool {
	return w.statusCode == 200 && strings.Contains(w.statusText, "Condition Intercepted")
}

// isDistilWAF checks for Distil (Distil Networks)
func (w *WAFDetector) isDistilWAF() bool {
	return w.matchContent(`cdn\.distilnetworks\.com/images/anomaly\.detected\.png`) ||
		w.matchContent(`distilCaptchaForm`) ||
		w.matchContent(`distilCallbackGuard`)
}

// isDOSarrestWAF checks for DOSarrest (DOSarrest Internet Security)
func (w *WAFDetector) isDOSarrestWAF() bool {
	return w.matchHeader("X-DIS-Request-ID", ".+") ||
		w.matchHeader("Server", `DOSarrest(.*)?`)
}

// isDotDefenderWAF checks for DotDefender (Applicure Technologies)
func (w *WAFDetector) isDotDefenderWAF() bool {
	return w.matchHeader("X-dotDefender-denied", `.+?`) ||
		w.matchContent(`dotdefender blocked your request`) ||
		w.matchContent(`Applicure is the leading provider of web application security`)
}

// isDynamicWebInjCheckWAF checks for DynamicWeb Injection Check (DynamicWeb)
func (w *WAFDetector) isDynamicWebInjCheckWAF() bool {
	return w.matchHeader("X-403-Status-By", `dw.inj.check`) ||
		w.matchContent(`by dynamic check(.{0,10}?module)?`)
}

// isEdgecastWAF checks for Edgecast (Verizon Digital Media)
func (w *WAFDetector) isEdgecastWAF() bool {
	return w.matchHeader("Server", `^ECD(.+)?`) ||
		w.matchHeader("Server", `^ECS(.*)?`)
}

// isEisooCloudFirewallWAF checks for Eisoo Cloud Firewall (Eisoo)
func (w *WAFDetector) isEisooCloudFirewallWAF() bool {
	return w.matchHeader("Server", `EisooWAF(\-AZURE)?/?`) ||
		w.matchContent(`<link.{0,10}?href=\"/eisoo\-firewall\-block\.css`) ||
		w.matchContent(`www\.eisoo\.com`) ||
		w.matchContent(`&copy; \d{4} Eisoo Inc`)
}

// isEnvoyWAF checks for Envoy (EnvoyProxy)
func (w *WAFDetector) isEnvoyWAF() bool {
	return w.matchHeader("server", "envoy") ||
		w.matchHeader("x-envoy-upstream-service-time", ".+") ||
		w.matchHeader("x-envoy-downstream-service-cluster", ".+") ||
		w.matchHeader("x-envoy-downstream-service-node", ".+") ||
		w.matchHeader("x-envoy-external-address", ".+") ||
		w.matchHeader("x-envoy-force-trace", ".+") ||
		w.matchHeader("x-envoy-internal", ".+") ||
		w.matchHeader("x-envoy-original-dst-host", ".+") ||
		w.matchHeader("x-envoy-original-path", ".+") ||
		w.matchHeader("x-envoy-local-overloaded", ".+")
}

// isExpressionEngineWAF checks for Expression Engine (EllisLab)
func (w *WAFDetector) isExpressionEngineWAF() bool {
	return w.matchCookie(`^exp_track.+?=`) ||
		w.matchCookie(`^exp_last_.+?=`) ||
		w.matchContent(`invalid get data`)
}

// isBigIpApManagerWAF checks for BIG-IP AP Manager (F5 Networks)
func (w *WAFDetector) isBigIpApManagerWAF() bool {
	return w.checkBigIpSchema01() || w.checkBigIpSchema02() || w.checkBigIpSchema03()
}

func (w *WAFDetector) checkBigIpSchema01() bool {
	return w.matchCookie(`^LastMRH_Session`) && w.matchCookie(`^MRHSession`)
}

func (w *WAFDetector) checkBigIpSchema02() bool {
	return w.matchCookie(`^MRHSession`) && w.matchHeader("Server", `Big([-_])?IP`)
}

func (w *WAFDetector) checkBigIpSchema03() bool {
	return w.matchCookie(`^F5_fullWT`) || w.matchCookie(`^F5_HT_shrinked`)
}

// isF5BigIPAppSec checks for BIG-IP AppSec Manager (F5 Networks) cookies
func (w *WAFDetector) isF5BigIPAppSec() (bool, string) {
	if w.matchCookie(`TS[a-fA-F0-9]{8}=`) {
		return true, "BIG-IP AppSec Manager (F5 Networks) ≥ v11.4.0 detected."
	}
	if w.matchCookie(`TS[a-fA-F0-9]{6}=`) {
		return true, "BIG-IP AppSec Manager (F5 Networks) v10.0.0–v11.3.0 detected."
	}
	return false, ""
}

// isBigIpLTMWAF checks for BIG-IP Local Traffic Manager (F5 Networks)
func (w *WAFDetector) isBigIpLTMWAF() bool {
	return w.matchCookie(`^bigipserver`) ||
		w.matchHeader("X-Cnection", "close")
}

// isFirePassWAF checks for FirePass (F5 Networks)
func (w *WAFDetector) isFirePassWAF() bool {
	return w.checkFirePassSchema01() || w.checkFirePassSchema02()
}

func (w *WAFDetector) checkFirePassSchema01() bool {
	return w.matchCookie(`^VHOST`) &&
		w.matchHeader("Location", `\/my\.logon\.php3`)
}

func (w *WAFDetector) checkFirePassSchema02() bool {
	return w.matchCookie(`^F5_fire.+?`) &&
		w.matchCookie(`^F5_passid_shrinked`)
}

// isTrafficShieldWAF checks for TrafficShield (F5 Networks)
func (w *WAFDetector) isTrafficShieldWAF() bool {
	return w.matchCookie(`^ASINFO=`) ||
		w.matchHeader("Server", "F5-TrafficShield")
}

// isFastlyWAF checks for Fastly (Fastly CDN)
func (w *WAFDetector) isFastlyWAF() bool {
	return w.matchHeader("X-Fastly-Request-ID", `\w+`)
}

// isFortiGateWAF checks for FortiGate (Fortinet)
func (w *WAFDetector) isFortiGateWAF() bool {
	return w.checkFortiGateSchema01() || w.checkFortiGateSchema02()
}

func (w *WAFDetector) checkFortiGateSchema01() bool {
	return w.matchContent(`//globalurl.fortinet.net`) &&
		w.matchContent(`FortiGate Application Control`)
}

func (w *WAFDetector) checkFortiGateSchema02() bool {
	return w.matchContent(`Web Application Firewall`) &&
		w.matchContent(`Event ID`) &&
		w.matchContent(`//globalurl.fortinet.net`)
}

// isFortiGuardWAF checks for FortiGuard (Fortinet)
func (w *WAFDetector) isFortiGuardWAF() bool {
	return w.checkFortiGuardSchema()
}

func (w *WAFDetector) checkFortiGuardSchema() bool {
	return w.matchContent(`FortiGuard Intrusion Prevention`) &&
		w.matchContent(`//globalurl.fortinet.net`) &&
		w.matchContent(`<title>Web Filter Violation`)
}

// isFortiWebWAF checks for FortiWeb (Fortinet)
func (w *WAFDetector) isFortiWebWAF() bool {
	return w.checkFortiWebSchema01() || w.checkFortiWebSchema02()
}

func (w *WAFDetector) checkFortiWebSchema01() bool {
	return w.matchCookie(`^FORTIWAFSID=`) ||
		w.matchContent(`fgd_icon`)
}

func (w *WAFDetector) checkFortiWebSchema02() bool {
	return w.matchContent(`fgd_icon`) &&
		w.matchContent(`web.page.blocked`) &&
		w.matchContent(`url`) &&
		w.matchContent(`attack.id`) &&
		w.matchContent(`message.id`) &&
		w.matchContent(`client.ip`)
}

// isAzureFrontDoorWAF checks for Azure Front Door (Microsoft)
func (w *WAFDetector) isAzureFrontDoorWAF() bool {
	return w.matchHeader("X-Azure-Ref", `.+?`)
}

// isGcloudArmorWAF checks for Google Cloud Armor
func (w *WAFDetector) isGcloudArmorWAF() bool {
	return w.matchHeader("Via", "1.1 google")
}

// isGoDaddyWAF checks for GoDaddy Website Protection
func (w *WAFDetector) isGoDaddyWAF() bool {
	return w.matchContent(`GoDaddy (security|website firewall)`)
}

// isGreywizardWAF checks for Grey Wizard
func (w *WAFDetector) isGreywizardWAF() bool {
	return w.matchHeader("Server", "greywizard") ||
		w.matchContent(`<(title|h\d{1})>Grey Wizard`) ||
		w.matchContent(`contact the website owner or Grey Wizard`) ||
		w.matchContent(`We.ve detected attempted attack or non standard traffic from your ip address`)
}

// isHuaweiCloudWAF checks for Huawei Cloud Firewall
func (w *WAFDetector) isHuaweiCloudWAF() bool {
	return w.matchCookie(`^HWWAFSESID=`) ||
		w.matchHeader("Server", `HuaweiCloudWAF`) ||
		w.matchContent(`hwclouds\.com`) ||
		w.matchContent(`hws_security@`)
}

// isHyperGuardWAF checks for HyperGuard (Art of Defense)
func (w *WAFDetector) isHyperGuardWAF() bool {
	return w.matchCookie(`^WODSESSION=`)
}

// isDataPowerWAF checks for IBM DataPower
func (w *WAFDetector) isDataPowerWAF() bool {
	return w.matchHeader("X-Backside-Transport", `(OK|FAIL)`)
}

// isImunify360WAF checks for Imunify360 (CloudLinux)
func (w *WAFDetector) isImunify360WAF() bool {
	return w.matchHeader("Server", `imunify360.{0,10}?`) ||
		w.matchContent(`protected.by.{0,10}?imunify360`) ||
		w.matchContent(`powered.by.{0,10}?imunify360`) ||
		w.matchContent(`imunify360.preloader`)
}

// isIncapsulaWAF checks for Incapsula (Imperva Inc.)
func (w *WAFDetector) isIncapsulaWAF() bool {
	return w.matchCookie(`^incap_ses.*?=`) ||
		w.matchCookie(`^visid_incap.*?=`) ||
		w.matchContent(`incapsula incident id`) ||
		w.matchContent(`powered by incapsula`) ||
		w.matchContent(`/_Incapsula_Resource`)
}

// isIndusGuardWAF checks for IndusGuard (Indusface)
func (w *WAFDetector) isIndusGuardWAF() bool {
	return w.matchHeader("Server", `IF_WAF`) ||
		w.matchContent(`This website is secured against online attacks. Your request was blocked`)
}

// isInstartDXWAF checks for Instart DX (Instart Logic)
func (w *WAFDetector) isInstartDXWAF() bool {
	return w.checkInstartDXSchema01() || w.checkInstartDXSchema02()
}

func (w *WAFDetector) checkInstartDXSchema01() bool {
	return w.matchHeader("X-Instart-Request-ID", ".+") ||
		w.matchHeader("X-Instart-Cache", ".+") ||
		w.matchHeader("X-Instart-WL", ".+")
}

func (w *WAFDetector) checkInstartDXSchema02() bool {
	return w.matchContent(`the requested url was rejected`) &&
		w.matchContent(`please consult with your administrator`) &&
		w.matchContent(`your support id is`)
}

// isISAserverWAF checks for ISA Server (Microsoft)
func (w *WAFDetector) isISAserverWAF() bool {
	return w.matchContent(`The.{0,10}?(isa.)?server.{0,10}?denied the specified uniform resource locator \(url\)`)
}

// isJanusecWAF checks for Janusec Application Gateway (Janusec)
func (w *WAFDetector) isJanusecWAF() bool {
	return w.matchContent(`janusec application gateway`)
}

// isJiasuleWAF checks for Jiasule
func (w *WAFDetector) isJiasuleWAF() bool {
	return w.matchHeader("Server", `jiasule\-waf`) ||
		w.matchCookie(`^jsl_tracking(.+)?=`) ||
		w.matchCookie(`__jsluid=`) ||
		w.matchContent(`notice\-jiasule`) ||
		w.matchContent(`static\.jiasule\.com`)
}

// isKempLoadMasterWAF checks for Kemp LoadMaster
func (w *WAFDetector) isKempLoadMasterWAF() bool {
	return w.matchHeader("X-ServedBy", "KEMP-LM") &&
		w.statusCode == 403 &&
		w.matchContent(`<title>403 Forbidden</title>`)
}

// isKeyCDNWAF checks for KeyCDN
func (w *WAFDetector) isKeyCDNWAF() bool {
	return w.matchHeader("Server", "KeyCDN")
}

// isKsWAF checks for KS-WAF (KnownSec)
func (w *WAFDetector) isKsWAF() bool {
	return w.matchContent(`/ks[-_]waf[-_]error\.png`)
}

// isKonaSiteDefenderWAF checks for Kona SiteDefender (Akamai)
func (w *WAFDetector) isKonaSiteDefenderWAF() bool {
	return w.matchHeader("Server", "AkamaiGHost")
}

// isLimeLightCDNWAF checks for LimeLight CDN (LimeLight)
func (w *WAFDetector) isLimeLightCDNWAF() bool {
	return w.matchCookie(`^limelight`) ||
		w.matchCookie(`^l[mg]_sessid=`)
}

// isLink11WAAPWAF checks for Link11 WAAP (Link11)
func (w *WAFDetector) isLink11WAAPWAF() bool {
	return w.matchHeader("server", "rhino-core-shield")
}

// isLiteSpeedWAF checks for LiteSpeed
func (w *WAFDetector) isLiteSpeedWAF() bool {
	return w.checkLiteSpeedSchema01() || w.checkLiteSpeedSchema02()
}

func (w *WAFDetector) checkLiteSpeedSchema01() bool {
	return w.matchHeader("Server", "LiteSpeed") && w.statusCode == 403
}

func (w *WAFDetector) checkLiteSpeedSchema02() bool {
	return w.matchContent(`Proudly powered by litespeed web server`) ||
		w.matchContent(`www\.litespeedtech\.com/error\-page`)
}

// isMalcareWAF checks for Malcare
func (w *WAFDetector) isMalcareWAF() bool {
	return w.matchContent(`firewall.{0,15}?powered.by.{0,15}?malcare.{0,15}?pro`) ||
		w.matchContent(`blocked because of malicious activities`)
}

// isMaxCDNWAF checks for MaxCDN
func (w *WAFDetector) isMaxCDNWAF() bool {
	return w.matchHeader("X-CDN", `maxcdn`)
}

// isMissionControlShieldWAF checks for Mission Control Shield
func (w *WAFDetector) isMissionControlShieldWAF() bool {
	return w.matchHeader("Server", "Mission Control Application Shield")
}

// isModSecurityWAF checks for ModSecurity (SpiderLabs)
func (w *WAFDetector) isModSecurityWAF() bool {
	return w.checkModSecuritySchema01() || w.checkModSecuritySchema02() || w.checkModSecuritySchema03()
}

func (w *WAFDetector) checkModSecuritySchema01() bool {
	if w.matchHeader("Server", `(?i)(mod_security|Mod_Security|NOYB)`) {
		return true
	}
	if w.matchContent(`(?i)This error was generated by Mod\.?Security`) {
		return true
	}
	if w.matchContent(`(?i)rules of the mod\.security\.module`) {
		return true
	}
	if w.matchContent(`(?i)mod\.security\.rules triggered`) {
		return true
	}
	if w.matchContent(`(?i)Protected by Mod\.?Security`) {
		return true
	}
	if w.matchContent(`(?i)/modsecurity[\-_]errorpage/`) {
		return true
	}
	if w.matchContent(`(?i)modsecurity iis`) {
		return true
	}
	return false
}

func (w *WAFDetector) checkModSecuritySchema02() bool {
	return w.statusCode == 403 && strings.Contains(w.statusText, "ModSecurity Action")
}

func (w *WAFDetector) checkModSecuritySchema03() bool {
	return w.statusCode == 406 && strings.Contains(w.statusText, "ModSecurity Action")
}

// isNaxsiWAF checks for NAXSI (NBS Systems)
func (w *WAFDetector) isNaxsiWAF() bool {
	if w.matchHeader("X-Data-Origin", `(?i)^naxsi(.+)?`) {
		return true
	}
	if w.matchHeader("Server", `(?i)naxsi(.+)?`) {
		return true
	}
	if w.matchContent(`(?i)blocked by naxsi`) {
		return true
	}
	if w.matchContent(`(?i)naxsi blocked information`) {
		return true
	}
	return false
}

// isNemesidaWAF checks for Nemesida (PentestIt)
func (w *WAFDetector) isNemesidaWAF() bool {
	if w.matchContent(`(?i)@?nemesida(\-security)?\.com`) {
		return true
	}
	if w.matchContent(`(?i)Suspicious activity detected.{0,10}?Access to the site is blocked`) {
		return true
	}
	if w.matchContent(`(?i)nwaf@`) {
		return true
	}
	if w.statusCode == 222 {
		return true
	}
	return false
}

// isNetContinuumWAF checks for NetContinuum (Barracuda Networks)
func (w *WAFDetector) isNetContinuumWAF() bool {
	return w.matchCookie(`^NCI__SessionId=`)
}

// isNetScalerAppFirewallWAF checks for NetScaler AppFirewall (Citrix Systems)
func (w *WAFDetector) isNetScalerAppFirewallWAF() bool {
	// Via header check (non-intrusive)
	if w.matchHeader("Via", `(?i)NS\-CACHE`) {
		return true
	}

	// Cookie-based detection
	if w.matchCookie(`^(ns_af=|citrix_ns_id|NSC_)`) {
		return true
	}

	// Content-based detection
	if w.matchContent(`(?i)(NS Transaction|AppFW Session) id`) {
		return true
	}
	if w.matchContent(`(?i)Violation Category.{0,5}?APPFW_`) {
		return true
	}
	if w.matchContent(`(?i)Citrix\|NetScaler`) {
		return true
	}

	// Header-based detection (case-sensitive, attack-only)
	if w.matchHeader("Cneonction", `(?i)^(keep alive|close)`) {
		return true
	}
	if w.matchHeader("nnCoection", `(?i)^(keep alive|close)`) {
		return true
	}

	return false
}

// isNevisProxyWAF checks for NevisProxy (AdNovum)
func (w *WAFDetector) isNevisProxyWAF() bool {
	return w.matchCookie(`^Navajo`) || w.matchCookie(`^NP_ID`)
}

// isNewdefendWAF checks for Newdefend (NewDefend)
func (w *WAFDetector) isNewdefendWAF() bool {
	// Server header check (most reliable)
	if w.matchHeader("Server", `(?i)Newdefend`) {
		return true
	}

	// Content-based detection
	if w.matchContent(`(?i)www\.newdefend\.com/feedback`) {
		return true
	}
	if w.matchContent(`(?i)/nd\-block/`) {
		return true
	}

	return false
}

// isNexusGuardFirewallWAF checks for NexusGuard Firewall (NexusGuard)
func (w *WAFDetector) isNexusGuardFirewallWAF() bool {
	if w.matchContent(`(?i)Powered by Nexusguard`) {
		return true
	}
	if w.matchContent(`(?i)nexusguard\.com/wafpage/.+#\d{3};`) {
		return true
	}
	return false
}

// isNinjaFirewallWAF checks for NinjaFirewall (NinTechNet)
func (w *WAFDetector) isNinjaFirewallWAF() bool {
	if !w.matchContent(`(?i)<title>NinjaFirewall.{0,10}?\d{3}.forbidden`) {
		return false
	}
	if !w.matchContent(`(?i)For security reasons?.{0,10}?it was blocked and logged`) {
		return false
	}
	return true
}

// isNSFocusWAF checks for NSFocus (NSFocus Global Inc.)
func (w *WAFDetector) isNSFocusWAF() bool {
	return w.matchHeader("Server", `(?i)NSFocus`)
}

// isNullDDoSProtectionWAF checks for NullDDoS Protection (NullDDoS)
func (w *WAFDetector) isNullDDoSProtectionWAF() bool {
	return w.matchHeader("Server", `(?i)NullDDoS(.System)?`)
}

// isOnMessageShieldWAF checks for OnMessage Shield (BlackBaud)
func (w *WAFDetector) isOnMessageShieldWAF() bool {
	if w.matchHeader("X-Engine", `(?i)onMessage Shield`) {
		return true
	}
	if w.matchContent(`(?i)Blackbaud K\-12 conducts routine maintenance`) {
		return true
	}
	if w.matchContent(`(?i)onMessage SHEILD`) {
		return true
	}
	if w.matchContent(`(?i)maintenance\.blackbaud\.com`) {
		return true
	}
	if w.matchContent(`(?i)status\.blackbaud\.com`) {
		return true
	}
	return false
}

// isOpenRestyLuaNginxWAF checks for Open-Resty Lua Nginx (FLOSS)
func (w *WAFDetector) isOpenRestyLuaNginxWAF() bool {
	return w.checkOpenRestySchema01() || w.checkOpenRestySchema02()
}

func (w *WAFDetector) checkOpenRestySchema01() bool {
	if !w.matchHeader("Server", `(?i)^openresty/[0-9\.]+`) {
		return false
	}
	return w.statusCode == 403
}

func (w *WAFDetector) checkOpenRestySchema02() bool {
	if !w.matchContent(`(?i)openresty/[0-9\.]+`) {
		return false
	}
	return w.statusCode == 406
}

// isOracleCloudWAF checks for Oracle Cloud (Oracle)
func (w *WAFDetector) isOracleCloudWAF() bool {
	if w.matchContent(`(?i)<title>fw_error_www`) {
		return true
	}
	if w.matchContent(`(?i)src="/oralogo_small\.gif"`) {
		return true
	}
	if w.matchContent(`(?i)www\.oracleimg\.com/us/assets/metrics/ora_ocom\.js`) {
		return true
	}
	return false
}

// isPaloAltoNextGenFirewallWAF checks for Palo Alto Next Gen Firewall (Palo Alto Networks)
func (w *WAFDetector) isPaloAltoNextGenFirewallWAF() bool {
	if w.matchContent(`(?i)Download of virus\.spyware blocked`) {
		return true
	}
	if w.matchContent(`(?i)Palo Alto Next Generation Security Platform`) {
		return true
	}
	return false
}

// is360PanYunWAF checks for 360PanYun (360 Technologies)
func (w *WAFDetector) is360PanYunWAF() bool {
	if w.matchHeader("Server", `(?i)panyun`) {
		return true
	}
	if w.matchHeader("X-Panyun-Request-ID", `.+?`) {
		return true
	}
	if w.matchHeader("X-Panyun-Error-Reason", `.+?`) {
		return true
	}
	if w.matchHeader("X-Panyun-Error-Step", `.+?`) {
		return true
	}
	return false
}

// isPentaWAFWAF checks for PentaWAF (Global Network Services)
func (w *WAFDetector) isPentaWAFWAF() bool {
	if w.matchHeader("Server", `(?i)PentaWaf(/[0-9\.]+)?`) {
		return true
	}
	if w.matchContent(`(?i)Penta.?Waf/[0-9\.]+?.server`) {
		return true
	}
	return false
}

// isPerimeterXWAF checks for PerimeterX (PerimeterX)
func (w *WAFDetector) isPerimeterXWAF() bool {
	if w.matchContent(`(?i)www\.perimeterx\.(com|net)/whywasiblocked`) {
		return true
	}
	if w.matchContent(`(?i)client\.perimeterx\.(net|com)`) {
		return true
	}
	if w.matchContent(`(?i)denied because we believe you are using automation tools`) {
		return true
	}
	return false
}

// isPkSecurityIDS checks for pkSecurity IDS (pkSec)
func (w *WAFDetector) isPkSecurityIDS() bool {
	return w.checkPkSecuritySchema01() || w.checkPkSecuritySchema02()
}

func (w *WAFDetector) checkPkSecuritySchema01() bool {
	if w.matchContent(`(?i)pk.?Security.?Module`) {
		return true
	}
	if w.matchContent(`(?i)Security\.Alert`) {
		return true
	}
	return false
}

func (w *WAFDetector) checkPkSecuritySchema02() bool {
	if !w.matchContent(`(?i)As this could be a potential hack attack`) {
		return false
	}
	if !w.matchContent(`(?i)A safety critical (call|request) was (detected|discovered) and blocked`) {
		return false
	}
	if !w.matchContent(`(?i)maximum number of reloads per minute and prevented access`) {
		return false
	}
	return true
}

// isPowerCDNWAF checks for PowerCDN (PowerCDN)
func (w *WAFDetector) isPowerCDNWAF() bool {
	if w.matchHeader("Via", `(?i)(.*)?powercdn\.com(.*)?`) {
		return true
	}
	if w.matchHeader("X-Cache", `(?i)(.*)?powercdn\.com(.*)?`) {
		return true
	}
	if w.matchHeader("X-CDN", `(?i)PowerCDN`) {
		return true
	}
	return false
}

// isProfenseWAF checks for Profense (ArmorLogic)
func (w *WAFDetector) isProfenseWAF() bool {
	if w.matchHeader("Server", `(?i)Profense`) {
		return true
	}
	if w.matchCookie(`^PLBSID=`) {
		return true
	}
	return false
}

// isPTApplicationFirewallWAF checks for PT Application Firewall (Positive Technologies)
func (w *WAFDetector) isPTApplicationFirewallWAF() bool {
	if !w.matchContent(`(?i)<h1.{0,10}?Forbidden`) {
		return false
	}
	if !w.matchContent(`(?i)<pre>Request\.ID:.{0,10}?\d{4}\-(\d{2})+.{0,35}?pre>`) {
		return false
	}
	return true
}

// isPuhuiWAF checks for Puhui (Puhui)
func (w *WAFDetector) isPuhuiWAF() bool {
	return w.matchHeader("Server", `(?i)Puhui[\-_]?WAF`)
}

// isQcloudWAF checks for Qcloud (Tencent Cloud)
func (w *WAFDetector) isQcloudWAF() bool {
	if !w.matchContent(`(?i)腾讯云Web应用防火墙`) {
		return false
	}
	return w.statusCode == 403
}

// isQiniuWAF checks for Qiniu (Qiniu CDN)
func (w *WAFDetector) isQiniuWAF() bool {
	return w.matchHeader("X-Qiniu-CDN", `\d+`)
}

// isQratorWAF checks for Qrator (Qrator)
func (w *WAFDetector) isQratorWAF() bool {
	return w.matchHeader("Server", `(?i)QRATOR`)
}

// isAppWallWAF checks for AppWall (Radware)
func (w *WAFDetector) isAppWallWAF() bool {
	return w.checkAppWallSchema01() || w.checkAppWallSchema02()
}

func (w *WAFDetector) checkAppWallSchema01() bool {
	if w.matchContent(`(?i)CloudWebSec\.radware\.com`) {
		return true
	}
	if w.matchHeader("X-SL-CompState", `.+`) {
		return true
	}
	return false
}

func (w *WAFDetector) checkAppWallSchema02() bool {
	if !w.matchContent(`(?i)because we have detected unauthorized activity`) {
		return false
	}
	if !w.matchContent(`(?i)<title>Unauthorized Request Blocked`) {
		return false
	}
	if !w.matchContent(`(?i)if you believe that there has been some mistake`) {
		return false
	}
	if !w.matchContent(`(?i)\?Subject=Security Page.{0,10}?Case Number`) {
		return false
	}
	return true
}

// isReblazeWAF checks for Reblaze (Reblaze)
func (w *WAFDetector) isReblazeWAF() bool {
	return w.checkReblazeSchema01() || w.checkReblazeSchema02()
}

func (w *WAFDetector) checkReblazeSchema01() bool {
	if w.matchCookie(`^rbzid`) {
		return true
	}
	if w.matchHeader("Server", `(?i)Reblaze Secure Web Gateway`) {
		return true
	}
	return false
}

func (w *WAFDetector) checkReblazeSchema02() bool {
	if !w.matchContent(`(?i)current session has been terminated`) {
		return false
	}
	if !w.matchContent(`(?i)do not hesitate to contact us`) {
		return false
	}
	if !w.matchContent(`(?i)access denied \(\d{3}\)`) {
		return false
	}
	return true
}

// isReflectedNetworksWAF checks for Reflected Networks
func (w *WAFDetector) isReflectedNetworksWAF() bool {
	return w.statusCode == 403 &&
		w.matchContent(`<img class="logo loader" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAbgAAABHCAIAAAD6G8WcAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyRpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw`) &&
		w.matchContent(`content="Request is denied"`) &&
		w.matchContent(`<title>Forbidden</title>`)
}

// isRSFirewallWAF checks for RSFirewall (RSJoomla!)
func (w *WAFDetector) isRSFirewallWAF() bool {
	return w.matchContent(`(?i)com_rsfirewall_(\d{3}_forbidden|event)?`)
}

// isRequestValidationModeWAF checks for RequestValidationMode (Microsoft)
func (w *WAFDetector) isRequestValidationModeWAF() bool {
	if w.matchContent(`(?i)Request Validation has detected a potentially dangerous client input`) {
		return true
	}
	if w.matchContent(`(?i)ASP\.NET has detected data in the request`) {
		return true
	}
	if w.matchContent(`(?i)HttpRequestValidationException`) {
		return true
	}
	return false
}

// isSabreFirewallWAF checks for Sabre Firewall (Sabre)
func (w *WAFDetector) isSabreFirewallWAF() bool {
	if w.matchContent(`(?i)dxsupport\.sabre\.com`) {
		return true
	}
	return w.checkSabreSchema01()
}

func (w *WAFDetector) checkSabreSchema01() bool {
	if !w.matchContent(`(?i)<title>Application Firewall Error`) {
		return false
	}
	if !w.matchContent(`(?i)add some important details to the email for us to investigate`) {
		return false
	}
	return true
}

// isSafe3WebFirewallWAF checks for Safe3 Web Firewall (Safe3)
func (w *WAFDetector) isSafe3WebFirewallWAF() bool {
	if w.matchHeader("Server", `(?i)Safe3 Web Firewall`) {
		return true
	}
	if w.matchHeader("X-Powered-By", `(?i)Safe3WAF/[\.0-9]+`) {
		return true
	}
	if w.matchContent(`(?i)Safe3waf/[0-9\.]+`) {
		return true
	}
	return false
}

// isSafedogWAF checks for Safedog (SafeDog)
func (w *WAFDetector) isSafedogWAF() bool {
	if w.matchCookie(`(?i)^safedog\-flow\-item=`) {
		return true
	}
	if w.matchHeader("Server", `(?i)Safedog`) {
		return true
	}
	if w.matchContent(`(?i)safedogsite/broswer_logo\.jpg`) {
		return true
	}
	if w.matchContent(`(?i)404\.safedog\.cn/sitedog_stat\.html`) {
		return true
	}
	if w.matchContent(`(?i)404\.safedog\.cn/images/safedogsite/head\.png`) {
		return true
	}
	return false
}

// isSafelineWAF checks for Safeline (Chaitin Tech.)
func (w *WAFDetector) isSafelineWAF() bool {
	return w.matchContent(`(?i)safeline|<!\-\-\sevent id:`)
}

// isSecKingWAF checks for SecKing (SecKing)
func (w *WAFDetector) isSecKingWAF() bool {
	return w.matchHeader("Server", `(?i)secking(.?waf)?`)
}

// isSecuPressWPSecurityWAF checks for SecuPress WP Security (SecuPress)
func (w *WAFDetector) isSecuPressWPSecurityWAF() bool {
	return w.matchContent(`(?i)<(title|h\d{1})>SecuPress`)
}

// isSecureEntryWAF checks for Secure Entry (United Security Providers)
func (w *WAFDetector) isSecureEntryWAF() bool {
	return w.matchHeader("Server", `(?i)Secure Entry Server`)
}

// isEeyeSecureIISWAF checks for eEye SecureIIS (BeyondTrust)
func (w *WAFDetector) isEeyeSecureIISWAF() bool {
	if w.matchContent(`(?i)SecureIIS is an internet security application`) {
		return true
	}
	if w.matchContent(`(?i)Download SecureIIS Personal Edition`) {
		return true
	}
	if w.matchContent(`(?i)https?://www\.eeye\.com/Secure\-?IIS`) {
		return true
	}
	return false
}

// isSecureSphereWAF checks for SecureSphere (Imperva Inc.)
func (w *WAFDetector) isSecureSphereWAF() bool {
	if !w.matchContent(`(?i)<(title|h2)>Error`) {
		return false
	}
	if !w.matchContent(`(?i)The incident ID is`) {
		return false
	}
	if !w.matchContent(`(?i)This page can't be displayed`) {
		return false
	}
	if !w.matchContent(`(?i)Contact support for additional information`) {
		return false
	}
	return true
}

// isSENginxWAF checks for SEnginx (Neusoft)
func (w *WAFDetector) isSENginxWAF() bool {
	return w.matchContent(`(?i)SENGINX\-ROBOT\-MITIGATION`)
}

// isServerDefenderVPWAF checks for ServerDefender VP (Port80 Software)
func (w *WAFDetector) isServerDefenderVPWAF() bool {
	return w.matchHeader("X-Pint", `(?i)p(ort\-)?80`)
}

// isShadowDaemonWAF checks for Shadow Daemon (Zecure)
func (w *WAFDetector) isShadowDaemonWAF() bool {
	if !w.matchContent(`(?i)<h\d{1}>\d{3}.forbidden<.h\d{1}>`) {
		return false
	}
	if !w.matchContent(`(?i)request forbidden by administrative rules`) {
		return false
	}
	return true
}

// isShieldonFirewallWAF checks for Shieldon Firewall (Shieldon.io)
func (w *WAFDetector) isShieldonFirewallWAF() bool {
	if w.checkShieldonSchema01() {
		return true
	}

	if w.checkShieldonSchema02() {
		return true
	}

	if w.checkShieldonSchema03() {
		return true
	}

	// Check for X-Protected-By header with shieldon.io value (case-insensitive header name)
	headerPattern := regexp.MustCompile(`(?i)^X-Protected-By$`)
	valuePattern := regexp.MustCompile(`(?i)shieldon\.io`)
	for headerName, values := range w.headers {
		if headerPattern.MatchString(headerName) {
			for _, value := range values {
				if valuePattern.MatchString(value) {
					return true
				}
			}
		}
	}

	return false
}

func (w *WAFDetector) checkShieldonSchema01() bool {
	if !w.matchContent(`(?i)Please solve CAPTCHA`) {
		return false
	}

	if !w.matchContent(`(?i)shieldon_captcha`) {
		return false
	}

	if !w.matchContent(`(?i)Unusual behavior detected`) {
		return false
	}

	if !w.matchContent(`(?i)status-user-info`) {
		return false
	}

	return true
}

func (w *WAFDetector) checkShieldonSchema02() bool {
	if !w.matchContent(`(?i)Access denied`) {
		return false
	}

	if !w.matchContent(`(?i)The IP address you are using has been blocked\.`) {
		return false
	}

	if !w.matchContent(`(?i)status-user-info`) {
		return false
	}

	return true
}

func (w *WAFDetector) checkShieldonSchema03() bool {
	if !w.matchContent(`(?i)Please line up`) {
		return false
	}

	if !w.matchContent(`(?i)This page is limiting the number of people online\. Please wait a moment\.`) {
		return false
	}

	return true
}

// isShieldSecurityWAF checks for Shield Security (One Dollar Plugin)
func (w *WAFDetector) isShieldSecurityWAF() bool {
	if w.matchContent(`(?i)You were blocked by the Shield`) {
		return true
	}
	if w.matchContent(`(?i)remaining transgression\(s\) against this site`) {
		return true
	}
	if w.matchContent(`(?i)Something in the URL.{0,5}?Form or Cookie data wasn't appropriate`) {
		return true
	}
	return false
}

// isSiteGroundWAF checks for SiteGround (SiteGround)
func (w *WAFDetector) isSiteGroundWAF() bool {
	if w.matchContent(`(?i)Our system thinks you might be a robot!`) {
		return true
	}
	if w.matchContent(`(?i)access is restricted due to a security rule`) {
		return true
	}
	return false
}

// isSiteGuardWAF checks for SiteGuard (EG Secure Solutions Inc.)
func (w *WAFDetector) isSiteGuardWAF() bool {
	if w.matchContent(`(?i)Powered by SiteGuard`) {
		return true
	}
	if w.matchContent(`(?i)The server refuse to browse the page`) {
		return true
	}
	return false
}

// isSitelockWAF checks for Sitelock (TrueShield)
func (w *WAFDetector) isSitelockWAF() bool {
	if w.matchContent(`(?i)SiteLock will remember you`) {
		return true
	}
	if w.matchContent(`(?i)Sitelock is leader in Business Website Security Services`) {
		return true
	}
	if w.matchContent(`(?i)sitelock[_\-]shield([_\-]logo|[\-_]badge)?`) {
		return true
	}
	if w.matchContent(`(?i)SiteLock incident ID`) {
		return true
	}
	return false
}

// isSonicWallWAF checks for SonicWall (Dell)
func (w *WAFDetector) isSonicWallWAF() bool {
	if w.matchHeader("Server", `(?i)SonicWALL`) {
		return true
	}
	if w.matchContent(`(?i)<(title|h\d{1})>Web Site Blocked`) {
		return true
	}
	if w.matchContent(`(?i)\+?nsa_banner`) {
		return true
	}
	return false
}

// isUTMWebProtectionWAF checks for UTM Web Protection (Sophos)
func (w *WAFDetector) isUTMWebProtectionWAF() bool {
	return w.checkUTMWebProtectionSchema01() || w.checkUTMWebProtectionSchema02()
}

func (w *WAFDetector) checkUTMWebProtectionSchema01() bool {
	if w.matchContent(`(?i)www\.sophos\.com`) {
		return true
	}
	if w.matchContent(`(?i)Powered by.?(Sophos)? UTM Web Protection`) {
		return true
	}
	return false
}

func (w *WAFDetector) checkUTMWebProtectionSchema02() bool {
	if !w.matchContent(`(?i)<title>Access to the requested URL was blocked`) {
		return false
	}
	if !w.matchContent(`(?i)Access to the requested URL was blocked`) {
		return false
	}
	if !w.matchContent(`(?i)incident was logged with the following log identifier`) {
		return false
	}
	if !w.matchContent(`(?i)Inbound Anomaly Score exceeded`) {
		return false
	}
	if !w.matchContent(`(?i)Your cache administrator is`) {
		return false
	}
	return true
}

// isSquarespaceWAF checks for Squarespace (Squarespace)
func (w *WAFDetector) isSquarespaceWAF() bool {
	if w.matchHeader("Server", `(?i)Squarespace`) {
		return true
	}
	if w.matchCookie(`^SS_ANALYTICS_ID=`) {
		return true
	}
	if w.matchCookie(`^SS_MATTR=`) {
		return true
	}
	if w.matchCookie(`^SS_MID=`) {
		return true
	}
	if w.matchCookie(`^SS_CVT=`) {
		return true
	}
	if w.matchContent(`(?i)status\.squarespace\.com`) {
		return true
	}
	if w.matchContent(`(?i)BRICK\-\d{2}`) {
		return true
	}
	return false
}

// isSquidProxyIDS checks for SquidProxy IDS (SquidProxy)
func (w *WAFDetector) isSquidProxyIDS() bool {
	if !w.matchHeader("Server", `(?i)squid(/[0-9\.]+)?`) {
		return false
	}
	if !w.matchContent(`(?i)Access control configuration prevents your request`) {
		return false
	}
	return true
}

// isStackPathWAF checks for StackPath
func (w *WAFDetector) isStackPathWAF() bool {
	return w.checkStackPathSchema01() || w.checkStackPathSchema02()
}

func (w *WAFDetector) checkStackPathSchema01() bool {
	return w.matchContent(`<title>StackPath[^<]+</title>`) ||
		w.matchContent(`Protected by <a href="https?:\/\/(?:www\.)?stackpath\.com\/"[^>]*>StackPath`)
}

func (w *WAFDetector) checkStackPathSchema02() bool {
	return w.matchContent(`is using a security service for protection against online attacks`) &&
		w.matchContent(`An action has triggered the service and blocked your request`)
}

// isSucuriCloudProxyWAF checks for Sucuri CloudProxy
func (w *WAFDetector) isSucuriCloudProxyWAF() bool {
	return w.matchHeader("X-Sucuri-ID", `.+?`) ||
		w.matchHeader("X-Sucuri-Cache", `.+?`) ||
		w.matchHeader("Server", `Sucuri(\-Cloudproxy)?`) ||
		w.matchHeader("X-Sucuri-Block", `.+?`) ||
		w.matchContent(`Access Denied.{0,6}?Sucuri Website Firewall`) ||
		w.matchContent(`<title>Sucuri WebSite Firewall.{0,6}?(CloudProxy)?.{0,6}?Access Denied`) ||
		w.matchContent(`sucuri\.net/privacy\-policy`) ||
		w.matchContent(`cdn\.sucuri\.net/sucuri[-_]firewall[-_]block\.css`) ||
		w.matchContent(`cloudproxy@sucuri\.net`)
}

// isTencentCloudWAF checks for Tencent Cloud Firewall (Tencent Technologies)
func (w *WAFDetector) isTencentCloudWAF() bool {
	return w.matchContent(`waf\.tencent\-?cloud\.com/`) ||
		w.matchContent(`window\.location\.href.{1,3}?https?://waf.tencent(?:-?cloud)?.com/(?:403|501)page\.html`)
}

// isTerosWAF checks for Teros (Citrix Systems)
func (w *WAFDetector) isTerosWAF() bool {
	return w.matchCookie(`^st8id=`)
}

// isThreatXWAF checks for ThreatX (A10 Networks)
func (w *WAFDetector) isThreatXWAF() bool {
	return w.matchHeader("X-Request-Id", `.*`) &&
		w.matchContent(`^Forbidden - ID: ([a-fA-F0-9]{32})$`) &&
		w.statusCode == 403
}

// isTransIPWebFirewallWAF checks for TransIP Web Firewall
func (w *WAFDetector) isTransIPWebFirewallWAF() bool {
	return w.matchHeader("X-TransIP-Backend", `.+`) ||
		w.matchHeader("X-TransIP-Balancer", `.+`)
}

// isUEWafWAF checks for UEWaf (UCloud)
func (w *WAFDetector) isUEWafWAF() bool {
	return w.matchHeader("Server", `uewaf(/[0-9\.]+)?`) ||
		w.matchContent(`/uewaf_deny_pages/default/img/`) ||
		w.matchContent(`ucloud\.cn`)
}

// isURLMasterSecurityCheckWAF checks for URLMaster SecurityCheck
func (w *WAFDetector) isURLMasterSecurityCheckWAF() bool {
	return w.checkURLMasterSchema01() || w.checkURLMasterSchema02()
}

func (w *WAFDetector) checkURLMasterSchema01() bool {
	return w.matchHeader("X-UrlMaster-Debug", `.+`) ||
		w.matchHeader("X-UrlMaster-Ex", `.+`)
}

func (w *WAFDetector) checkURLMasterSchema02() bool {
	return w.matchContent(`Ur[li]RewriteModule`) &&
		w.matchContent(`SecurityCheck`)
}

// isURLScanWAF checks for URLScan (Microsoft)
func (w *WAFDetector) isURLScanWAF() bool {
	return w.matchContent(`Rejected[-_]By[_-]UrlScan`) ||
		w.matchContent(`A custom filter or module.{0,4}?such as URLScan`)
}

// isVaritiWAF checks for Variti
func (w *WAFDetector) isVaritiWAF() bool {
	return w.matchHeader("Server", `Variti(?:\/[a-z0-9\.\-]+)?`)
}

// isVarnishOWASPWAF checks for Varnish (OWASP)
func (w *WAFDetector) isVarnishOWASPWAF() bool {
	return w.matchContent(`Request rejected by xVarnish\-WAF`)
}

// isVercelWAF checks for Vercel WAF (Vercel)
func (w *WAFDetector) isVercelWAF() bool {
	return w.matchContent(`<title>Vercel Security Checkpoint</title>`) ||
		w.matchContent(`/vercel/security/`)
}

// isViettelWAF checks for Viettel (Cloudrity)
func (w *WAFDetector) isViettelWAF() bool {
	return w.matchContent(`Access Denied.{0,10}?Viettel WAF`) ||
		w.matchContent(`cloudrity\.com\.(vn)?/`) ||
		w.matchContent(`Viettel WAF System`)
}

// isVirusDieWAF checks for VirusDie (VirusDie LLC)
func (w *WAFDetector) isVirusDieWAF() bool {
	return w.matchContent(`cdn\.virusdie\.ru/splash/firewallstop\.png`) ||
		w.matchContent(`copy.{0,10}?Virusdie\.ru`)
}

// isWallarmWAF checks for Wallarm (Wallarm Inc.)
func (w *WAFDetector) isWallarmWAF() bool {
	return w.matchHeader("Server", `nginx[\-_]wallarm`)
}

// isWatchGuardWAF checks for WatchGuard (WatchGuard Technologies)
func (w *WAFDetector) isWatchGuardWAF() bool {
	return w.matchHeader("Server", "WatchGuard") ||
		w.matchContent(`Request denied by WatchGuard Firewall`) ||
		w.matchContent(`WatchGuard Technologies Inc\.`)
}

// isWebARXWAF checks for WebARX (WebARX Security Solutions)
func (w *WAFDetector) isWebARXWAF() bool {
	return w.matchContent(`WebARX.{0,10}?Web Application Firewall`) ||
		w.matchContent(`www\.webarxsecurity\.com`) ||
		w.matchContent(`/wp\-content/plugins/webarx/includes/`)
}

// isWebKnightWAF checks for WebKnight (AQTRONIX)
func (w *WAFDetector) isWebKnightWAF() bool {
	return w.checkWebKnightSchema01() ||
		w.checkWebKnightSchema02() ||
		w.checkWebKnightSchema03()
}

func (w *WAFDetector) checkWebKnightSchema01() bool {
	return w.statusCode == 999 && strings.Contains(w.statusText, "No Hacking")
}

func (w *WAFDetector) checkWebKnightSchema02() bool {
	return w.statusCode == 404 && strings.Contains(w.statusText, "Hack Not Found")
}

func (w *WAFDetector) checkWebKnightSchema03() bool {
	return w.matchContent(`WebKnight Application Firewall Alert`) ||
		w.matchContent(`What is webknight\?`) ||
		w.matchContent(`AQTRONIX WebKnight is an application firewall`) ||
		w.matchContent(`WebKnight will take over and protect`) ||
		w.matchContent(`aqtronix\.com/WebKnight`) ||
		w.matchContent(`AQTRONIX.{0,10}?WebKnight`)
}

// isWebLandWAF checks for WebLand
func (w *WAFDetector) isWebLandWAF() bool {
	return w.matchHeader("Server", `protected by webland`)
}

// isRayWAF checks for RayWAF (WebRay Solutions)
func (w *WAFDetector) isRayWAF() bool {
	return w.matchHeader("Server", `WebRay\-WAF`) ||
		w.matchHeader("DrivedBy", `RaySrv\.RayEng/[0-9\.]+?`)
}

// isWebSEALWAF checks for WebSEAL (IBM)
func (w *WAFDetector) isWebSEALWAF() bool {
	return w.matchHeader("Server", "WebSEAL") ||
		w.matchContent(`This is a WebSEAL error message template file`) ||
		w.matchContent(`WebSEAL server received an invalid HTTP request`)
}

// isWebTotemWAF checks for WebTotem
func (w *WAFDetector) isWebTotemWAF() bool {
	return w.matchContent(`The current request was blocked.{0,8}?>WebTotem`)
}

// isWest263CDNWAF checks for West263 CDN (West263CDN)
func (w *WAFDetector) isWest263CDNWAF() bool {
	return w.matchHeader("X-Cache", `WS?T263CDN`)
}

// isWordfenceWAF checks for Wordfence (Defiant)
func (w *WAFDetector) isWordfenceWAF() bool {
	return w.matchHeader("Server", `wf[_\-]?WAF`) ||
		w.matchContent(`Generated by Wordfence`) ||
		w.matchContent(`broke one of (the )?Wordfence (advanced )?blocking rules`) ||
		w.matchContent(`/plugins/wordfence`)
}

// isWpmudevWAF checks for wpmudev WAF (Incsub)
func (w *WAFDetector) isWpmudevWAF() bool {
	return w.checkWpmudevSchema01() || w.checkWpmudevSchema02()
}

func (w *WAFDetector) checkWpmudevSchema01() bool {
	return w.matchContent(`href="http(s)?.\/\/wpmudev.com\/.{0,15}?`) &&
		w.matchContent(`Click on the Logs tab, then the WAF Log.`) &&
		w.matchContent(`Choose your site from the list`) &&
		w.statusCode == 403
}

func (w *WAFDetector) checkWpmudevSchema02() bool {
	return w.matchContent(`<h1>Whoops, this request has been blocked!`) &&
		w.matchContent(`This request has been deemed suspicious`) &&
		w.matchContent(`possible attack on our servers.`) &&
		w.statusCode == 403
}

// isWTSWAF checks for WTS-WAF (WTS)
func (w *WAFDetector) isWTSWAF() bool {
	return w.matchHeader("Server", `wts/[0-9\.]+?`) ||
		w.matchContent(`<(title|h\d{1})>WTS\-WAF`)
}

// is360WangZhanBaoWAF checks for 360WangZhanBao (360 Technologies)
func (w *WAFDetector) is360WangZhanBaoWAF() bool {
	return w.matchHeader("Server", `qianxin\-waf`) ||
		w.matchHeader("WZWS-Ray", `.+?`) ||
		w.matchHeader("X-Powered-By-360WZB", `.+?`) ||
		w.matchContent(`wzws\-waf\-cgi/`) ||
		w.matchContent(`wangshan\.360\.cn`) ||
		w.statusCode == 493
}

// isXLabsSecurityWAF checks for XLabs Security WAF (XLabs)
func (w *WAFDetector) isXLabsSecurityWAF() bool {
	return w.matchHeader("X-CDN", `XLabs Security`) ||
		w.matchHeader("Secured", `^By XLabs Security`) ||
		w.matchHeader("Server", `XLabs[-_]?.?WAF`)
}

// isXuanwudunWAF checks for Xuanwudun
func (w *WAFDetector) isXuanwudunWAF() bool {
	return w.matchContent(`admin\.dbappwaf\.cn/(index\.php/Admin/ClientMisinform/)?`) ||
		w.matchContent(`class=.(db[\-_]?)?waf(.)?([\-_]?row)?>`)
}

// isYundunWAF checks for Yundun
func (w *WAFDetector) isYundunWAF() bool {
	return w.matchHeader("Server", "YUNDUN") ||
		w.matchHeader("X-Cache", "YUNDUN") ||
		w.matchCookie(`^yd_cookie=`) ||
		w.matchContent(`Blocked by YUNDUN Cloud WAF`) ||
		w.matchContent(`yundun\.com/yd[-_]http[_-]error/`) ||
		w.matchContent(`www\.yundun\.com/(static/js/fingerprint\d{1}?\.js)?`)
}

// isYunsuoWAF checks for Yunsuo
func (w *WAFDetector) isYunsuoWAF() bool {
	return w.matchCookie(`^yunsuo_session=`) ||
		w.matchContent(`class="yunsuologo"`)
}

// isYXLinkWAF checks for YXLink (YxLink Technologies)
func (w *WAFDetector) isYXLinkWAF() bool {
	return w.matchCookie(`^yx_ci_session=`) ||
		w.matchCookie(`^yx_language=`) ||
		w.matchHeader("Server", `Yxlink([\-_]?WAF)?`)
}

// isZenedgeWAF checks for Zenedge
func (w *WAFDetector) isZenedgeWAF() bool {
	return w.matchHeader("Server", "ZENEDGE") ||
		w.matchHeader("X-Zen-Fury", `.+?`) ||
		w.matchContent(`/ __zenedge/`)
}

// isZScalerWAF checks for ZScaler (Accenture)
func (w *WAFDetector) isZScalerWAF() bool {
	return w.matchHeader("Server", `ZScaler`) ||
		w.matchContent(`Access Denied.{0,10}?Accenture Policy`) ||
		w.matchContent(`policies\.accenture\.com`) ||
		w.matchContent(`login\.zscloud\.net/img_logo_new1\.png`) ||
		w.matchContent(`Zscaler to protect you from internet threats`) ||
		w.matchContent(`Internet Security by ZScaler`) ||
		w.matchContent(`Accenture.{0,10}?webfilters indicate that the site likely contains`)
}

// matchHeader checks if a header matches a value using regex
func (w *WAFDetector) matchHeader(header, value string) bool {
	headerValue := w.headers.Get(header)
	if headerValue == "" {
		return false
	}
	return regexp.MustCompile(value).MatchString(headerValue)
}

// matchCookie checks if a cookie matches a regex pattern
func (w *WAFDetector) matchCookie(pattern string) bool {
	re := regexp.MustCompile(pattern)
	return re.MatchString(w.cookies)
}

// matchContent checks if the response body matches a regex pattern
func (w *WAFDetector) matchContent(pattern string) bool {
	re := regexp.MustCompile(pattern)
	return re.MatchString(w.body)
}

// WafDetect runs the full WAF-check pipeline and returns
// (true, "<product name>") when a WAF is recognised.
func WafDetect(raw string, port string) (bool, string) {
	if port == "" {
		port = "443"
	}
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")

	var finalURL string
	if port == "443" {
		finalURL = "https://" + raw
	} else {
		finalURL = "http://" + net.JoinHostPort(raw, port)
	}

	d := NewWAFDetector(finalURL)
	if err := d.DoRequest(); err != nil {
		fmt.Println(err)
		return false, ""
	}
	return d.IsWAF()
}
