<?php

/**
 * PHP Larvel Server-Side Example for Fine Uploader S3.
 *
 * This example:
 *  - A port version of PHP Server-Side Example for Fine Uploader S3
 *  - handles non-CORS/CORS environment depends on your laravel route/middleware configuration
 *  - handles size validation and no size validation
 *  - handles delete file requests for both DELETE and POST methods
 *  - Performs basic inspections on the policy documents and REST headers before signing them
 *  - Ensures again the file size does not exceed the max (after file is in S3)
 *  - signs policy documents (simple uploads) and REST requests
 *    (chunked/multipart uploads)
 *  - returns a thumbnailUrl in the response for older browsers so thumbnails can be displayed next to the file
 *
 * Requirements:
 *  - Larvel 5.0+
 *  - PHP 5.3 or newer
 *  - Amazon PHP SDK (only if utilizing the AWS SDK for deleting files or otherwise examining them)
 *
 * If you need to install the AWS SDK, see http://docs.aws.amazon.com/aws-sdk-php-2/guide/latest/installation.html.
 */

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Requests;
use App\Http\Controllers\Controller;
use Aws\S3\S3Client;
use Aws\Credentials\Credentials;

class ExampleController extends Controller
{
   private $clientPrivateKey;
   private $serverPublicKey;
   private $serverPrivateKey;
   private $expectedBucketName;
   private $expectedHostName; // v4-only
   private $expectedMaxSize;
   private $expectedBucketRegion;
   private $expectedBucketVersion;
   private $req;

   /**
     * Construct all the configs
     *
     * -the code below require your to set the environments under config/services.php
     * please see service.php for example, you can also direct set the environment
     * here for quick test
     */
   public function __construct(Request $req){
        $this->clientPrivateKey = config('services.amazon.clientPrivateKey');
        $this->serverPublicKey = config('services.amazon.serverPublicKey');
        $this->serverPrivateKey = config('services.amazon.serverPrivateKey');
        $this->expectedBucketName = config('services.amazon.expectedBucketName');
        $this->expectedHostName = config('services.amazon.expectedHostName');
        $this->expectedMaxSize = config('services.amazon.expectedMaxSize');
        $this->expectedBucketRegion = config('services.amazon.expectedBucketRegion');
        $this->expectedBucketVersion = config('services.amazon.expectedBucketVersion');
        $this->req = $req;
   }


   //the method your route point to
   public function endpoint(){
        if(isset($this->req->success)){
            //after successful upload
            //the request will contain the bucket and key at this point
            return $this->verifyFileInS3($this->shouldIncludeThumbnail());
        }else{
            //sign request handling
            return $this->signRequest();
        }
   }

   private function getS3Client() {
       $credentials = new Credentials($this->serverPublicKey,$this->serverPrivateKey);
       return new S3Client([
           'region' => $this->expectedBucketRegion,
           'version' => $this->expectedBucketVersion,
           'credentials' => $credentials
       ]);
   }

   private function signRequest() {
      $content = $this->req->getContent();
      $contentAsObject = json_decode($content, true);
      $jsonContent = json_encode($contentAsObject);
       if (isset($contentAsObject["headers"])) {
           return $this->signRestRequest($contentAsObject["headers"]);
       }
       else {
           return $this->signPolicy($jsonContent);
       }
   }

   private function signPolicy($policyStr) {
       $policyObj = json_decode($policyStr, true);
       if ($this->isPolicyValid($policyObj)) {
           $encodedPolicy = base64_encode($policyStr);
           if ($this->req->has('v4')) {
               $response = ['policy' => $encodedPolicy, 'signature' => $this->signV4Policy($encodedPolicy, $policyObj)];
           }
           else {
               $response = ['policy' => $encodedPolicy, 'signature' => $this->sign($encodedPolicy)];
           }
           return response()->json($response);
       }
       else {
           return response()->json(['invalid' => true]);
       }
   }

   private function signV4Policy($stringToSign, $policyObj) {
       foreach ($policyObj["conditions"] as $condition) {
           if (isset($condition["x-amz-credential"])) {
               $credentialCondition = $condition["x-amz-credential"];
           }
       }
       $pattern = "/.+\/(.+)\\/(.+)\/s3\/aws4_request/";
       preg_match($pattern, $credentialCondition, $matches);
       $dateKey = hash_hmac('sha256', $matches[1], 'AWS4' . $this->clientPrivateKey, true);
       $dateRegionKey = hash_hmac('sha256', $matches[2], $dateKey, true);
       $dateRegionServiceKey = hash_hmac('sha256', 's3', $dateRegionKey, true);
       $signingKey = hash_hmac('sha256', 'aws4_request', $dateRegionServiceKey, true);
       return hash_hmac('sha256', $stringToSign, $signingKey);
   }

   private function isPolicyValid($policy) {
       $conditions = $policy["conditions"];
       $bucket = null;
       $parsedMaxSize = null;
       for ($i = 0; $i < count($conditions); ++$i) {
           $condition = $conditions[$i];
           if (isset($condition["bucket"])) {
               $bucket = $condition["bucket"];
           }
           else if (isset($condition[0]) && $condition[0] == "content-length-range") {
               $parsedMaxSize = $condition[2];
           }
       }
       return $bucket == $this->expectedBucketName && $parsedMaxSize == (string)$this->expectedMaxSize;
   }

   private function signRestRequest($headersStr) {
       $version = $this->req->has('v4') ? 4 : 2;
       if ($this->isValidRestRequest($headersStr, $version)) {
           if ($version == 4) {
               $response = ['signature' => $this->signV4RestRequest($headersStr)];
           }
           else {
               $response = ['signature' => $this->sign($headersStr)];
           }
           return response()->json($response);
       }
       else {
           return response()->json(['invalid' => true]);
       }
   }

   private function sign($stringToSign) {
       return base64_encode(hash_hmac(
           'sha1',
           $stringToSign,
           $this->clientPrivateKey,
           true
       ));
   }

   private function signV4RestRequest($rawStringToSign) {
       $pattern = "/.+\\n.+\\n(\\d+)\/(.+)\/s3\/aws4_request\\n(.+)/s";
       preg_match($pattern, $rawStringToSign, $matches);
       $hashedCanonicalRequest = hash('sha256', $matches[3]);
       $stringToSign = preg_replace("/^(.+)\/s3\/aws4_request\\n.+$/s", '$1/s3/aws4_request'."\n".$hashedCanonicalRequest, $rawStringToSign);
       $dateKey = hash_hmac('sha256', $matches[1], 'AWS4' . $this->clientPrivateKey, true);
       $dateRegionKey = hash_hmac('sha256', $matches[2], $dateKey, true);
       $dateRegionServiceKey = hash_hmac('sha256', 's3', $dateRegionKey, true);
       $signingKey = hash_hmac('sha256', 'aws4_request', $dateRegionServiceKey, true);
       return hash_hmac('sha256', $stringToSign, $signingKey);
   }

   private function isValidRestRequest($headersStr, $version) {
       if ($version == 2) {
           $expectedBucketName = $this->expectedBucketName;
           $pattern = "/\/$expectedBucketName\/.+$/";
       }
       else {
           $expectedHostName = $this->expectedHostName;
           $pattern = "/host:$expectedHostName/";
       }
       preg_match($pattern, $headersStr, $matches);
       return count($matches) > 0;
   }

   private function getObjectSize($bucket, $key) {
       $objInfo = $this->getS3Client()->headObject([
           'Bucket' => $bucket,
           'Key' => $key
       ]);
       return $objInfo['ContentLength'];
   }

   // Provide a time-bombed public link to the file.
   private function getTempLink($bucket, $key) {
       $client = $this->getS3Client();
       $url = "{$bucket}/{$key}";
       $cmd = $client->getCommand('GetObject',[
          'Bucket' => $bucket,
          'Key' => $key
       ]);
       $request = $client->createPresignedRequest($cmd, '+15 minutes');
       return (string) $request->getUri();
   }

   // Only needed if the delete file feature is enabled
   private function deleteObject() {
       $this->getS3Client()->deleteObject([
           'Bucket' => $this->req->bucket,
           'Key' => $this->req->key
       ]);
   }

   // This is not needed if you don't require a callback on upload success.
   private function verifyFileInS3($includeThumbnail) {
       $bucket = $this->req->bucket;
       $key = $this->req->key;
       if (isset($this->expectedMaxSize) && $this->getObjectSize($bucket, $key) > $this->expectedMaxSize) {
           $this->deleteObject();
           return response()->json(["error" => "File is too big!", "preventRetry" => true],500);
       }
       else {
           $link = $this->getTempLink($bucket, $key);
           $response =["tempLink" => $link];
           if ($includeThumbnail) {
               $response["thumbnailUrl"] = $link;
           }
           return response()->json($response);
       }
   }

   // Return true if it's likely that the associate file is natively
   // viewable in a browser.  For simplicity, just uses the file extension
   // to make this determination, along with an array of extensions that one
   // would expect all supported browsers are able to render natively.
   protected function isFileViewableImage($filename) {
       $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
       $viewableExtensions = array("jpeg", "jpg", "gif", "png","svg");
       return in_array($ext, $viewableExtensions);
   }

   // Returns true if we should attempt to include a link
   // to a thumbnail in the uploadSuccess response.  In it's simplest form
   // (which is our goal here - keep it simple) we only include a link to
   // a viewable image and only if the browser is not capable of generating a client-side preview.
   protected function shouldIncludeThumbnail() {
       $filename = $this->req->name;
       $isPreviewCapable = $this->req->isBrowserPreviewCapable == "true";
       $isFileViewableImage = $this->isFileViewableImage($filename);
       return !$isPreviewCapable && $isFileViewableImage;
   }
}