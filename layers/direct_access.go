package layers

import (
	"errors"
	"regexp"

	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"github.com/9seconds/httransform"
)

var errDirectAccess = errors.New("direct access to the URL")

type DirectAccessLayer struct {
	rules    []*regexp.Regexp
	notRules []*regexp.Regexp
	executor httransform.HTTPRequestExecutor
}

func (d *DirectAccessLayer) OnRequest(state *httransform.LayerState) error {
	url := state.Request.URI()
	hostpath := make([]byte, 0, len(url.Host())+len(url.RequestURI()))
	hostpath = append(hostpath, url.Host()...)
	hostpath = append(hostpath, url.RequestURI()...)

	logger := getLogger(state)
	logger.WithFields(log.Fields{"hostpath": string(hostpath)}).Debug("OnRequest")

	for _, v := range d.notRules {
		if v.Match(hostpath) {
			logger.WithFields(log.Fields{"hostpath": string(hostpath), "match": v.String()}).Debug("Match not rule")
			return nil
		}
	}

	for _, v := range d.rules {
		if v.Match(hostpath) {
			logger.WithFields(log.Fields{"hostpath": string(hostpath), "match": v.String()}).Debug("Match rule")
			return errDirectAccess
		}
	}

	return nil
}

func (d *DirectAccessLayer) OnResponse(state *httransform.LayerState, err error) {
	if err == errDirectAccess {
		httransform.HTTPExecutor(state)

		if err := httransform.ParseHeaders(state.ResponseHeaders, state.Response.Header.Header()); err != nil {
			logger := getLogger(state)
			logger.WithFields(log.Fields{"err": err}).Debug("Cannot process response")
			httransform.MakeSimpleResponse(state.Response, "Malformed response headers", fasthttp.StatusBadRequest)
		}
	}
}

func NewDirectAccessLayer(regexps []string, notregexps []string) httransform.Layer {
	rules := make([]*regexp.Regexp, len(regexps))
	for i, v := range regexps {
		rules[i] = regexp.MustCompile(v)
	}

	notRules := make([]*regexp.Regexp, len(notregexps))
	for i, v := range notregexps {
		notRules[i] = regexp.MustCompile(v)
	}

	return &DirectAccessLayer{
		rules:    rules,
		notRules: notRules,
		executor: httransform.MakeStreamingReuseHTTPClient(),
	}
}
