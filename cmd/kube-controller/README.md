# kube-controller

This controller integrates Kubernetes with the
[`token-server`](../cmd/token-server) by generating pull secrets that provide a
service account token as the password.

It uses the `TokenRequest` API to generate service account tokens and places them
in `kubernetes.io/dockerconfigjson` type secrets.  The secrets are attached to
the service accounts in the `spec.secrets` and `spec.imagePullSecrets` fields.

Putting the secret in `spec.imagePullSecrets` ensures it is used when pulling images
for pods.

Putting it in `spec.secrets` enables tools that support it (like Tekton) to
automatically make the credentials available for container clients that talk to
the registry from within a pod.

Here's a brief example of what the controller creates:

```
$ kubectl get secret default-pull-secret -o json | jq -r '.data[".dockerconfigjson"]' | base64 -d | jq -r .
{
  "auths": {
    "<hostname>": {
      "username": "username",
      "password": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkprYlpyV2YwSW5NanhJOTRxQ2FHSHJsclZweFRxbEs3ZTk2S0FVa2VsNWMifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlLXJlZ2lzdHJ5LnJpYmJ5YmliYnkubWUiXSwiZXhwIjoxNjg0NDI5OTg4LCJpYXQiOjE2ODQ0MjkzODgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImRlZmF1bHQiLCJ1aWQiOiI1YWJhYTUzMC02YmFkLTRkMjQtODc4Ni1kYWM5MDgzNDg3N2YifX0sIm5iZiI6MTY4NDQyOTM4OCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCJ9.hSOLU6YfRBQpgeDU_FCWfaquGoW4GpUjNYCnH-4VmhiErWK5j4JoUhF-Eh-wvWS-l7RnCEa9jCKAuCkID98lqBOqs6WnzCcQazEfAjP423rES8NcdBLx2umhkOqP6bdg_OKwJbOTdIbEh5MQ9PfCAjp3qQRnD0e5NNuKJb-fYNuHNteGFgmNf9lejGgd5qZHHmp_798oaPSuIh04OO8gYe6FX3hSHfT7OpqLf4glE5uMoAMh87vsOlV5HNMZfclyrm1rPxA9SBJoiA27AIxVW89YiaBEOuP7fBGMj3j6lmfQgw6djnokxhviTcs_G2ScK52YCerctAvnVPThF08GTA",
      "auth": "..."
    }
  }
}

$ kubectl get serviceaccount default -o yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: default
imagePullSecrets:
  # Used by the kubelet when pulling images for pods that use this service
  # account
  - name: default-pull-secret
secrets:
  # Made available inside containers when running pods with Tekton
  - name: default-pull-secret
```
