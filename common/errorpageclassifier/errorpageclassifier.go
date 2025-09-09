package errorpageclassifier

import (
	_ "embed"

	htmltomarkdown "github.com/JohannesKaufmann/html-to-markdown/v2"
	"github.com/projectdiscovery/utils/ml/naive_bayes"
)

//go:embed clf.gob
var classifierData []byte

type ErrorPageClassifier struct {
	classifier *naive_bayes.NaiveBayesClassifier
}

func New() *ErrorPageClassifier {
	classifier, err := naive_bayes.NewClassifierFromFileData(classifierData)
	if err != nil {
		panic(err)
	}
	return &ErrorPageClassifier{classifier: classifier}
}

func (n *ErrorPageClassifier) Classify(html string) string {
	text := htmlToText(html)
	if text == "" {
		return "other"
	}
	return n.classifier.Classify(text)
}

func htmlToText(html string) string {
	text, err := htmltomarkdown.ConvertString(html)
	if err != nil {
		panic(err)
	}
	return text
}
