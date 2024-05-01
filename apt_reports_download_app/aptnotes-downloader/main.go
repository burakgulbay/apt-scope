package main

import (
	"aptnotes-downloader/structs"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func main() {
	reports := getAllReportsMetadata()
	var htmlText string
	var reportDownloadUrl string
	var err error

	for _, k := range reports {
		htmlText = getHtml(k.Link)
		reportDownloadUrl, err = getDownloadURL(htmlText)
		if err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Println("Download URL: ", reportDownloadUrl)
			err = downloadFile(reportDownloadUrl, k.Filename)
			if err != nil {
				fmt.Println("error while file download: ", err.Error())
			}
		}
	}
}

func getAllReportsMetadata() structs.Report {
	jsonFile, err := os.Open("APTnotes.json")
	if err != nil {
		fmt.Println(err)
	}

	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)

	var reports structs.Report

	json.Unmarshal(byteValue, &reports)

	// for i := 0; i < len(reports); i++ {
	// 	fmt.Println(i+1, " File Name: "+reports[i].Filename)
	// }
	return reports
}

func getHtml(link string) string {
	res, err := http.Get(link)
	if err != nil {
		log.Fatal(err)
	}
	content, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	return string(content)
}

func getDownloadURL(page string) (string, error) {
	// Parse HTML page
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(page))
	if err != nil {
		return "", err
	}

	// Find and extract script content
	var scriptContent string
	doc.Find("body script").Each(func(i int, s *goquery.Selection) {
		scriptContent = s.Text()
	})

	// Split script content into sections
	sections := strings.Split(scriptContent, ";")

	// Extract app_api JSON
	appAPIJSON := strings.Split(sections[len(sections)-2], "=")[1]
	var appAPI map[string]interface{}
	if err := json.Unmarshal([]byte(appAPIJSON), &appAPI); err != nil {
		return "", err
	}

	// Build download URL
	boxURL := "https://app.box.com/index.php"
	boxArgs := "?rm=box_download_shared_file&shared_name=%s&file_id=%s"

	appApiMap := appAPI["/app-api/enduserapp/shared-item"].(map[string]interface{})
	sharedName := appApiMap["sharedName"]
	itemID := fmt.Sprintf("%.0f", appApiMap["itemID"])
	fileURL := fmt.Sprintf(boxURL+boxArgs, sharedName, fmt.Sprintf("f_%v", itemID))

	return fileURL, nil
}

func downloadFile(URL, fileName string) error {
	//Get the response bytes from the url
	response, err := http.Get(URL)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return errors.New("Received non 200 response code")
	}
	//Create a empty file
	file, err := os.Create("downloaded/" + fileName + ".pdf")
	if err != nil {
		return err
	}
	defer file.Close()

	//Write the bytes to the fiel
	_, err = io.Copy(file, response.Body)
	if err != nil {
		return err
	}

	return nil
}
