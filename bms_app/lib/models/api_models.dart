typedef ClientHeaders = Map<String, String>;

class ClientRequestOptions {
  const ClientRequestOptions({this.headers = const <String, String>{}});

  final ClientHeaders headers;
}

class ClientHttpException implements Exception {
  const ClientHttpException({
    required this.statusCode,
    required this.message,
    required this.path,
  });

  final int statusCode;
  final String message;
  final String path;

  @override
  String toString() {
    return 'ClientHttpException(status=$statusCode, path=$path, message=$message)';
  }
}

