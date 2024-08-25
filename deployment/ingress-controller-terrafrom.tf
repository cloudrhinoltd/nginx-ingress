locals {
  ip_address = "<public_ip.k8s_pip>"
}

# Define the ConfigMap with your custom WAF configuration
resource "helm_release" "nginx_ingress_waf" {
  name       = "nginx-ingress-waf"
  chart      = "ingress-nginx"
  repository = "https://kubernetes.github.io/ingress-nginx"
  namespace  = "kube-system"

  values = [
    <<-YAML
    controller:
      extraArgs: 
        http-port: 8888
        https-port: 8883
    YAML
  ]

  set {
    name  = "controller.service.loadBalancerIP"
    value = local.ip_address
  }

  set {
    name  = "controller.allowSnippetAnnotations"
    value = "true"
  }

  set {
    name  = "controller.replicaCount"
    value = "1"
  }

  set {
    name  = "controller.ingressClassResource.name"
    value = "nginx-waf"
  }

  set {
    name  = "controller.ingressClassResource.controllerValue"
    value = "k8s.io/ingress-nginx-waf"
  }

  set {
    name  = "controller.service.externalTrafficPolicy"
    value = "Local"
  }

  set {
    name  = "controller.service.annotations.service\\.beta\\.kubernetes\\.io/azure-load-balancer-health-probe-request-path"
    value = "/healthz"
  }


  set {
    name  = "controller.config.error-log-level"
    value = "debug"
  }

  set {
    name  = "controller.image.pullPolicy"
    value = "Always"
  }

  set {
    name  = "controller.image.registry"
    value = "dvsharedcisacr.azurecr.io"
  }

  set {
    name  = "controller.image.repository"
    value = "dvsharedcisacr.azurecr.io/aks-waf"
  }

  set {
    name  = "controller.image.tag"
    value = "1.0.0"
  }

  set {
    name  = "controller.image.digest"
    value = ""
  }
}

# Get the service
data "kubernetes_service" "nginx_service_waf" {
  metadata {
    name      = "nginx-ingress-waf-ingress-nginx-controller"
    namespace = "kube-system"
  }

  depends_on = [helm_release.nginx_ingress_waf]
}


resource "null_resource" "update_nginx_ingress_waf_configmap" {
  triggers = {
    always_run = "${timestamp()}"
  }
  provisioner "local-exec" {
    command = <<EOT
    # Set variables
    CONFIGMAP_NAME="${helm_release.nginx_ingress_waf.name}-ingress-nginx-controller"
    NAMESPACE="kube-system"
    CURRENT_CONFIGMAP_FILE="current-configmap.yaml"
    LOCATION_SNIPPET_FILE="./charts/clrh-waf/location-snippet.yaml"
    MERGED_CONFIGMAP_FILE="merged-configmap.yaml"

    # Step 1: Pull the current ConfigMap into a file
    kubectl get configmap $CONFIGMAP_NAME -n $NAMESPACE -o yaml > $CURRENT_CONFIGMAP_FILE

    # Step 2: Drop the existing 'location-snippet' if it exists
    yq eval 'del(.data["location-snippet"])' $CURRENT_CONFIGMAP_FILE > $MERGED_CONFIGMAP_FILE

    # Step 3: Insert the content of location-snippet.yaml directly into the ConfigMap
    # Find the line with "data:" and append the location-snippet content right after it
    sed -e '/^data:/r '"$LOCATION_SNIPPET_FILE"'' $MERGED_CONFIGMAP_FILE > temp-configmap.yaml && mv temp-configmap.yaml $MERGED_CONFIGMAP_FILE

    # Step 4: Apply the updated ConfigMap
    kubectl apply -f $MERGED_CONFIGMAP_FILE

    # Cleanup temporary files
    rm $CURRENT_CONFIGMAP_FILE
    rm $MERGED_CONFIGMAP_FILE

    echo "ConfigMap $CONFIGMAP_NAME updated successfully in namespace $NAMESPACE."
    EOT
  }

  depends_on = [
    helm_release.nginx_ingress_waf
  ]
}

data "external" "ingress_public_ip" {
  depends_on = [helm_release.nginx_ingress_waf]
  program    = ["bash", "${path.module}/get_lb_public_ip.sh", local.subscription, local.aks_rg_mc.name, "kubernetes"]
}

resource "kubernetes_job" "ingress_health_check" {
  depends_on = [
    helm_release.nginx_ingress_waf
  ]
  metadata {
    name      = "ingress-webhook-health-check"
    namespace = "kube-system" # Namespace where your ingress is deployed
  }

  spec {
    template {
      metadata {}
      spec {
        container {
          image   = "appropriate/curl" # Using a lightweight container image with curl
          name    = "webhook-check"
          command = ["sh", "-c", "until curl -k https://nginx-ingress-waf-ingress-nginx-controller-admission.kube-system.svc:443; do echo waiting for webhook; sleep 10; done"]
        }
        restart_policy = "OnFailure"
      }
    }

    backoff_limit = 3
  }
}