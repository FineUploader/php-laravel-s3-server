<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    | Path: config/services.php
    |
    | ... All your other services configuration
    |
    */

    'amazon' => [
        'clientPrivateKey' => env('AWS_CLIENT_SECRET_KEY'),
        'serverPublicKey' => env('AWS_SERVER_PUBLIC_KEY'),
        'serverPrivateKey' => env('AWS_SERVER_PRIVATE_KEY'),
        'expectedBucketName' => env('S3_BUCKET_NAME'),
        'expectedHostName' => env('S3_HOST_NAME'),
        'expectedMaxSize' => env('S3_MAX_FILE_SIZE',null),
        'expectedBucketRegion' => env('S3_BUCKET_REGION','us-east-1'),
        'expectedBucketVersion' => env('S3_BUCKET_VERSION','2006-03-01'),
    ]

];