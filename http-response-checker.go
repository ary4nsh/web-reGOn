package main

import (
 "fmt"
 "net/http"
 "os"

 "github.com/fatih/color"
)

func main() {
 if len(os.Args) < 2 {
  fmt.Println("Usage: go run main.go <url>")
  return
 }

 url := os.Args[1]
 resp, err := http.Get(url)
 if err != nil {
  fmt.Printf("Error fetching URL: %v\n", err)
  return
 }
 defer resp.Body.Close()

 // Get the response code
 statusCode := resp.StatusCode

 // Determine the color based on the response code
 var coloredOutput string
 switch {
 case statusCode >= 200 && statusCode < 300:
  coloredOutput = color.GreenString(fmt.Sprintf("HTTP Response Code: %d", statusCode))
 case statusCode >= 300 && statusCode < 400:
  coloredOutput = color.BlueString(fmt.Sprintf("HTTP Response Code: %d", statusCode))
 case statusCode >= 400 && statusCode < 500:
  coloredOutput = color.RedString(fmt.Sprintf("HTTP Response Code: %d", statusCode))
 case statusCode >= 500:
  coloredOutput = color.YellowString(fmt.Sprintf("HTTP Response Code: %d", statusCode)) // Using Yellow for Orange since color doesn't have direct support
 default:
  coloredOutput = fmt.Sprintf("HTTP Response Code: %d", statusCode)
 }

 // Print the colored output
 fmt.Println(coloredOutput)
}
