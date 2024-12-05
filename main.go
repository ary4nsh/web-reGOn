package main
import(
	"fmt"
	"net/http"
	"os"
	"bufio"
	"strings"
)

const (
	StatusContinue           = 100
	StatusSwitchingProtocols = 101
	StatusProcessing         = 102
	StatusEarlyHints         = 103

	StatusOK                   = 200
	StatusCreated              = 201
	StatusAccepted             = 202
	StatusNonAuthoritativeInfo = 203
	StatusNoContent            = 204
	StatusResetContent         = 205
	StatusPartialContent       = 206
	StatusMultiStatus          = 207
	StatusAlreadyReported      = 208
	StatusIMUsed               = 226

	StatusMultipleChoices  = 300
	StatusMovedPermanently = 301
	StatusFound            = 302
	StatusSeeOther         = 303
	StatusNotModified      = 304
	StatusUseProxy         = 305
	StatusTemporaryRedirect = 307
	StatusPermanentRedirect = 308

	StatusBadRequest                   = 400
	StatusUnauthorized                 = 401
	StatusPaymentRequired              = 402
	StatusForbidden                    = 403
	StatusNotFound                     = 404
	StatusMethodNotAllowed             = 405
	StatusNotAcceptable                = 406
	StatusProxyAuthRequired            = 407
	StatusRequestTimeout               = 408
	StatusConflict                     = 409
	StatusGone                         = 410
	StatusLengthRequired               = 411
	StatusPreconditionFailed           = 412
	StatusRequestEntityTooLarge        = 413
	StatusRequestURITooLong            = 414
	StatusUnsupportedMediaType         = 415
	StatusRequestedRangeNotSatisfiable = 416
	StatusExpectationFailed            = 417
	StatusMisdirectedRequest           = 421
	StatusUnprocessableEntity          = 422
	StatusLocked                       = 423
	StatusFailedDependency             = 424
	StatusTooEarly                     = 425
	StatusUpgradeRequired              = 426
	StatusPreconditionRequired         = 428
	StatusTooManyRequests              = 429
	StatusRequestHeaderFieldsTooLarge  = 431
	StatusUnavailableForLegalReasons   = 451

	StatusInternalServerError           = 500
	StatusNotImplemented                = 501
	StatusBadGateway                    = 502
	StatusServiceUnavailable            = 503
	StatusGatewayTimeout                = 504
	StatusHTTPVersionNotSupported       = 505
	StatusVariantAlsoNegotiates         = 506
	StatusInsufficientStorage           = 507
	StatusLoopDetected                  = 508
	StatusNotExtended                   = 510
	StatusNetworkAuthenticationRequired = 511
)

const (
	Reset = "\033[0m" //reset colors back to default after printing the colored texts
	Red = "\033[31m"
	Blue = "\033[34m"
	Green = "\033[32m"
	Orange = "\033[38;5;214m" //using 256-color mode
)

func main(){
	fmt.Println("Enter the URL: ")
	read := bufio.NewReader(os.Stdin)
	url, _ := read.ReadString('\n')
	
	url = strings.TrimSpace(url) //trim whitespace from url
	
	if url == ""{
		fmt.Println("Enter a valid URL: ")
		return
	}

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Connection was not establiched")
		return
	}

	defer resp.Body.Close()
	
	switch resp.StatusCode {
	case 200:
		fmt.Printf("%s %s[200]: OK%s", url, Green, Reset)
	case 404:
		fmt.Printf("%s %s[404]: Not Found%s", url, Red, Reset)
	default:
		fmt.Println("---")
	}


}






