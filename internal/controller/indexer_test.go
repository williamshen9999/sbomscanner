package controller

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/fields"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

var _ = Describe("SetupIndexer", func() {
	It("should setup all required indexes", func(ctx context.Context) {
		By("Creating a new manager")
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: k8sClient.Scheme(),
		})
		Expect(err).NotTo(HaveOccurred())

		By("Setting up the indexer")
		err = SetupIndexer(ctx, mgr)
		Expect(err).NotTo(HaveOccurred())

		By("Starting the manager")
		go func() {
			defer GinkgoRecover()
			err = mgr.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
		}()

		By("Waiting for the cache to sync")
		Eventually(func() bool {
			return mgr.GetCache().WaitForCacheSync(ctx)
		}).Should(BeTrue())

		// Verify indexes are working by attempting to list with them
		// This will fail if the indexes weren't properly set up
		By("Listing ScanJobs by registry and UID indexes")
		var scanJobList v1alpha1.ScanJobList
		err = mgr.GetClient().List(ctx, &scanJobList, &client.ListOptions{
			FieldSelector: fields.SelectorFromSet(fields.Set{
				v1alpha1.IndexScanJobSpecRegistry: "test-registry",
			}),
		})
		Expect(err).NotTo(HaveOccurred())

		By("Listing ScanJobs by UID index")
		err = mgr.GetClient().List(ctx, &scanJobList, &client.ListOptions{
			FieldSelector: fields.SelectorFromSet(fields.Set{
				v1alpha1.IndexScanJobMetadataUID: "test-uid",
			}),
		})
		Expect(err).NotTo(HaveOccurred())

		By("Listing Images by metadata index")
		var imageList storagev1alpha1.ImageList
		err = mgr.GetClient().List(ctx, &imageList, &client.ListOptions{
			FieldSelector: fields.SelectorFromSet(fields.Set{
				storagev1alpha1.IndexImageMetadataComposite: "docker.io/library/nginx:latest",
			}),
		})
		Expect(err).NotTo(HaveOccurred())

		By("Listing WorkloadScanReports by image ref index")
		var workloadList storagev1alpha1.WorkloadScanReportList
		err = mgr.GetClient().List(ctx, &workloadList, &client.ListOptions{
			FieldSelector: fields.SelectorFromSet(fields.Set{
				storagev1alpha1.IndexWorkloadScanReportImageRef: "default/docker.io/library/nginx:latest",
			}),
		})
		Expect(err).NotTo(HaveOccurred())
	})
})

func TestIndexImageByMetadata(t *testing.T) {
	tests := []struct {
		name     string
		object   client.Object
		expected []string
	}{
		{
			name: "returns composite key for an image",
			object: &storagev1alpha1.Image{
				ImageMetadata: storagev1alpha1.ImageMetadata{
					Registry:   "docker.io",
					Repository: "library/nginx",
					Tag:        "latest",
				},
			},
			expected: []string{"docker.io/library/nginx:latest"},
		},
		{
			name:     "returns nil for non-Image objects",
			object:   &storagev1alpha1.WorkloadScanReport{},
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keys := indexImageByMetadata(test.object)
			assert.Equal(t, test.expected, keys)
		})
	}
}

func TestIndexWorkloadByImageRef(t *testing.T) {
	tests := []struct {
		name     string
		object   client.Object
		expected []string
	}{
		{
			name: "returns composite keys for all unique container image refs",
			object: &storagev1alpha1.WorkloadScanReport{
				Spec: storagev1alpha1.WorkloadScanReportSpec{
					Containers: []storagev1alpha1.ContainerRef{
						{
							Name: "nginx",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "docker.io",
								Namespace:  "default",
								Repository: "library/nginx",
								Tag:        "latest",
							},
						},
						{
							Name: "sidecar",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "ghcr.io",
								Namespace:  "default",
								Repository: "org/sidecar",
								Tag:        "v1",
							},
						},
					},
				},
			},
			expected: []string{
				"default/docker.io/library/nginx:latest",
				"default/ghcr.io/org/sidecar:v1",
			},
		},
		{
			name: "deduplicates image refs",
			object: &storagev1alpha1.WorkloadScanReport{
				Spec: storagev1alpha1.WorkloadScanReportSpec{
					Containers: []storagev1alpha1.ContainerRef{
						{
							Name: "nginx-1",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "docker.io",
								Namespace:  "default",
								Repository: "library/nginx",
								Tag:        "latest",
							},
						},
						{
							Name: "nginx-2",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "docker.io",
								Namespace:  "default",
								Repository: "library/nginx",
								Tag:        "latest",
							},
						},
					},
				},
			},
			expected: []string{"default/docker.io/library/nginx:latest"},
		},
		{
			name:     "returns nil for non-WorkloadScanReport objects",
			object:   &storagev1alpha1.Image{},
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keys := indexWorkloadByImageRef(test.object)
			assert.Equal(t, test.expected, keys)
		})
	}
}
