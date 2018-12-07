package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Sirupsen/logrus"
	dockerapi "github.com/docker/docker/api"
	dockerclient "github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	"github.com/docker/engine-api/types/container"
	"github.com/docker/go-plugins-helpers/authorization"
)

func newPlugin(dockerHost, certPath string, tlsVerify bool) (*novolume, error) {
	var transport *http.Transport
	if certPath != "" {
		tlsc := &tls.Config{}

		cert, err := tls.LoadX509KeyPair(filepath.Join(certPath, "cert.pem"), filepath.Join(certPath, "key.pem"))
		if err != nil {
			return nil, fmt.Errorf("Error loading x509 key pair: %s", err)
		}

		tlsc.Certificates = append(tlsc.Certificates, cert)
		tlsc.InsecureSkipVerify = !tlsVerify
		transport = &http.Transport{
			TLSClientConfig: tlsc,
		}
	}

	client, err := dockerclient.NewClient(dockerHost, dockerapi.DefaultVersion.String(), transport, nil)
	if err != nil {
		return nil, err
	}
	return &novolume{client: client}, nil
}

var (
	// e.g. POST /v1.37/containers/create
	createRegExp = regexp.MustCompile(`^/[^\/]+/containers/create$`)
	// e.g. POST /v1.37/containers/189e08209b450e2f866b572f7d1263b12aaa1c8dcbbb5eb473c5e07db0f276d1/start
	startRegExp = regexp.MustCompile(`^/[^\/]+/containers/(.*)/start$`)
)

type novolume struct {
	client *dockerclient.Client
}

func logFieldsFromRequest(req authorization.Request) logrus.Fields {
	req.RequestBody = nil
	req.ResponseBody = nil
	return logrus.Fields{"request": req}
}

func inSlice(strs []string, str string) bool {
	for _, s := range strs {
		if str == s {
			return true
		}
	}
	return false
}

func (p *novolume) verifyHostConfig(hostConfig *container.HostConfig) error {
	// VolumesFrom are not allowed.
	if len(hostConfig.VolumesFrom) > 0 {
		return fmt.Errorf("hostConfig.VolumesFrom is not allowed: %v", hostConfig.VolumesFrom)
	}
	return nil
}

func (p *novolume) verifyContainerCreateConfig(config *types.ContainerCreateConfig) (err error) {
	err = p.verifyHostConfig(config.HostConfig)
	if err != nil {
		return
	}
	return nil
}

func (p *novolume) verifyContainer(container types.ContainerJSON) error {
	// Check all mounts are bind mounts only.
	bindDests := []string{}
	for _, m := range container.Mounts {
		if m.Driver != "" {
			return fmt.Errorf("container has non-bind-mount volume at %s, volume driver: %s", m.Destination, m.Driver)
		}
		bindDests = append(bindDests, m.Destination)
	}
	image, _, err := p.client.ImageInspectWithRaw(container.Image, false)
	if err != nil {
		return err
	}
	// Check all volumes are bindmounted.
	notBindMountedVolumes := []string{}
	for v, _ := range image.Config.Volumes {
		if !inSlice(bindDests, v) {
			notBindMountedVolumes = append(notBindMountedVolumes, v)
		}
	}
	if len(notBindMountedVolumes) > 0 {
		return fmt.Errorf("container has not-bind-mounted volumes: %s", strings.Join(notBindMountedVolumes, ","))
	}
	// Verify HostConfig.
	if err := p.verifyHostConfig(container.HostConfig); err != nil {
		return err
	}
	return nil
}

func (p *novolume) AuthZReq(req authorization.Request) authorization.Response {
	parsedURL, err := url.ParseRequestURI(req.RequestURI)
	if err != nil {
		return authorization.Response{Err: err.Error()}
	}
	logrus.WithField("requestURI", req.RequestURI).WithField("requestBody", string(req.RequestBody)).Debug("request")
	if req.RequestMethod == "POST" && createRegExp.MatchString(parsedURL.Path) {
		// Create container
		config := &types.ContainerCreateConfig{}
		if err := json.NewDecoder(bytes.NewReader(req.RequestBody)).Decode(config); err != nil {
			return authorization.Response{Err: err.Error()}
		}
		if err := p.verifyContainerCreateConfig(config); err != nil {
			logrus.WithFields(logFieldsFromRequest(req)).Info("request denied")
			return authorization.Response{Msg: err.Error()}
		}
	} else if req.RequestMethod == "POST" && startRegExp.MatchString(parsedURL.Path) {
		// Start container
		// Verify HostConfig first
		// Note that, starting from docker version 1.12.0 (api version: 1.24),
		// passing HostConfig at API container start is not supported.
		// See https://docs.docker.com/release-notes/docker-engine/#1120-2016-07-28.
		if req.RequestBody != nil {
			hostConfig := &container.HostConfig{}
			if err := json.NewDecoder(bytes.NewReader(req.RequestBody)).Decode(hostConfig); err != nil {
				return authorization.Response{Err: err.Error()}
			}
			if err := p.verifyHostConfig(hostConfig); err != nil {
				return authorization.Response{Err: err.Error()}
			}
		}
		// Inspect and verify container.
		res := startRegExp.FindStringSubmatch(parsedURL.Path)
		if len(res) < 1 {
			return authorization.Response{Err: "unable to find container name"}
		}
		container, err := p.client.ContainerInspect(res[1])
		if err != nil {
			return authorization.Response{Msg: err.Error()}
		}
		if err := p.verifyContainer(container); err != nil {
			logrus.WithFields(logFieldsFromRequest(req)).Info("request denied")
			return authorization.Response{Msg: err.Error()}
		}
	}
	logrus.WithFields(logFieldsFromRequest(req)).Info("request allowed")
	return authorization.Response{Allow: true}
}

func (p *novolume) AuthZRes(req authorization.Request) authorization.Response {
	return authorization.Response{Allow: true}
}
