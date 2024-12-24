package com.whiteoaksecurity.copier;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.whiteoaksecurity.copier.models.RequestRulesTableModel;
import com.whiteoaksecurity.copier.models.ResponseRulesTableModel;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class GlobalCopyProfile {

	private RequestRulesTableModel requestRulesTableModel;
	private ResponseRulesTableModel responseRulesTableModel;
	private boolean updateRequestContentLength = false;
	private boolean updateResponseContentLength = false;

	@JsonCreator
	public GlobalCopyProfile() {
		this.requestRulesTableModel = new RequestRulesTableModel();
		this.responseRulesTableModel = new ResponseRulesTableModel();
	}
	
	public boolean getUpdateRequestContentLength() {
		return this.updateRequestContentLength;
	}
	
	public boolean getUpdateResponseContentLength() {
		return this.updateResponseContentLength;
	}
	
	@JsonProperty("requestRules")
	public RequestRulesTableModel getRequestRulesTableModel() {
		return this.requestRulesTableModel;
	}
	
	@JsonProperty("responseRules")
	public ResponseRulesTableModel getResponseRulesTableModel() {
		return this.responseRulesTableModel;
	}

	public void setUpdateRequestContentLength(boolean update) {
		this.updateRequestContentLength = update;
	}
	
	public void setUpdateResponseContentLength(boolean update) {
		this.updateResponseContentLength = update;
	}

	public String getFirstLine(HttpMessage httpMessage) {
		String[] entireResponseAsArray = (new String(httpMessage.toByteArray().getBytes(), StandardCharsets.UTF_8)).lines().toList().toArray(new String[0]);
		if (entireResponseAsArray.length > 0) {
			return entireResponseAsArray[0];
		} else {
			return null;
		}
	}

	public HttpRequestResponse replace(HttpRequestResponse requestResponse, boolean replaceRequest, boolean replaceResponse) {
		ArrayList<HttpRequestResponse> temp = new ArrayList<>();
		temp.add(requestResponse);
		return this.replace(temp, replaceRequest, replaceResponse).get(0);
	}
	
	public ArrayList<HttpRequestResponse> replace(List<HttpRequestResponse> requestResponses, boolean replaceRequest, boolean replaceResponse) {
		ArrayList<HttpRequestResponse> modified = new ArrayList<>();

		for (HttpRequestResponse httpRequestResponse : requestResponses) {

			HttpRequest httpRequest = httpRequestResponse.request();
			boolean isHTTP2 = false;
			
			// Convert HTTP/2 to HTTP/1.1 while performing match / replace rules.
			if (httpRequest.httpVersion() != null && httpRequest.httpVersion().equals("HTTP/2")) {
				isHTTP2 = true;
				httpRequest = HttpRequest.httpRequest(httpRequest.toByteArray());
			}
			
			Integer requestContentLength = null;
			for (HttpHeader h : httpRequest.headers()) {
				if (h.name().trim().equalsIgnoreCase("Content-Length")) {
					try {
						requestContentLength = Integer.parseInt(h.value().trim());
					} catch (NumberFormatException e) {}

					break;
				}
			}

			// HTTP/2 responses appear to get treated the same way as HTTP/1.1 by Burp.
			HttpResponse httpResponse = httpRequestResponse.response();
			
			if (replaceRequest) {
				for (Rule replacement : this.getRequestRulesTableModel().getData()) {
					if (replacement.isEnabled()) {
						try {
							switch (replacement.getLocation()) {
								// Entire Request
								case 0 -> {
									String entireRequest = httpRequest.toByteArray().toString();
									httpRequest = HttpRequest.httpRequest(httpRequest.httpService(), replacement.getPattern().matcher(entireRequest).replaceAll(replacement.getReplace()));
									break;
								}
								// Request Line
								case 1 -> {
									String[] entireRequestAsArray = httpRequest.toByteArray().toString().lines().toList().toArray(new String[0]);
									if (entireRequestAsArray.length > 0) {
										entireRequestAsArray[0] = replacement.getPattern().matcher(entireRequestAsArray[0]).replaceAll(replacement.getReplace());
									} else {
										break;
									}



									httpRequest = HttpRequest.httpRequest(httpRequest.httpService(), String.join("\r\n", entireRequestAsArray));
									break;
								}
								// Request URL Param
								case 2 -> {
									String entireRequest = httpRequest.toByteArray().toString();
									List<ParsedHttpParameter> params = httpRequest.parameters();
									List<HttpParameter> updatedParams = new ArrayList<>();
									for (ParsedHttpParameter param : params) {
										if (param.type().equals(HttpParameterType.URL)) {
											String paramString = replacement.getPattern().matcher(entireRequest.substring(param.nameOffsets().startIndexInclusive(), param.valueOffsets().endIndexExclusive())).replaceAll(replacement.getReplace());
											// If param is now empty, we don't add it back to the request.
											if (!paramString.isEmpty()) {
												String[] keyValue = paramString.split("=", 2);
												if (keyValue.length == 2) {
													updatedParams.add(HttpParameter.urlParameter(keyValue[0], keyValue[1]));
												} else if (keyValue.length == 1) {
													updatedParams.add(HttpParameter.urlParameter(keyValue[0], ""));
												}
											}
										} else {
											updatedParams.add(param);
										}

										// We have to remove each param individually and then add them back later for some reason.
										httpRequest = httpRequest.withRemovedParameters(param);
									}
									httpRequest = httpRequest.withAddedParameters(updatedParams);
									break;
								}
								// Request URL Param Name
								case 3 -> {
									List<ParsedHttpParameter> params = httpRequest.parameters();
									List<HttpParameter> updatedParams = new ArrayList<>();
									for (ParsedHttpParameter param : params) {
										if (param.type().equals(HttpParameterType.URL)) {
											String paramName = replacement.getPattern().matcher(param.name()).replaceAll(replacement.getReplace());
											// If param name is now empty, we don't add it back to the request.
											if (!paramName.isEmpty()) {
												updatedParams.add(HttpParameter.urlParameter(paramName, param.value()));
											}
										} else {
											updatedParams.add(param);
										}

										// We have to remove each param individually and then add them back later for some reason.
										httpRequest = httpRequest.withRemovedParameters(param);
									}
									httpRequest = httpRequest.withAddedParameters(updatedParams);
									break;
								}
								// Request URL Param Value
								case 4 -> {
									List<ParsedHttpParameter> params = httpRequest.parameters();
									List<HttpParameter> updatedParams = new ArrayList<>();
									for (ParsedHttpParameter param : params) {
										if (param.type().equals(HttpParameterType.URL)) {
											String paramValue = replacement.getPattern().matcher(param.value()).replaceAll(replacement.getReplace());
											updatedParams.add(HttpParameter.urlParameter(param.name(), paramValue));
										} else {
											updatedParams.add(param);
										}

										// We have to remove each param individually and then add them back later for some reason.
										httpRequest = httpRequest.withRemovedParameters(param);
									}
									httpRequest = httpRequest.withAddedParameters(updatedParams);
									break;
								}
								// Request Headers
								case 5 -> {
									String headers = httpRequest.toByteArray().toString().substring(0, httpRequest.bodyOffset());
									String linebreak = "\r\n";
									if (!headers.contains(linebreak)) {
										linebreak = "\n";
									}
									headers = replacement.getPattern().matcher(headers.strip() + linebreak).replaceAll(replacement.getReplace());
									// Remove blank lines.
									while (headers.contains("\r\n\r\n") || headers.contains("\n\n")) {
										headers = headers.replaceAll("\r\n\r\n", "\r\n").replaceAll("\n\n", "\n");
									}
									
									httpRequest = HttpRequest.httpRequest(httpRequest.httpService(), headers + linebreak + httpRequest.bodyToString());
									break;
								}
								// Request Header
								case 6 -> {
									List<HttpHeader> headers = httpRequest.headers();
									List<HttpHeader> updatedHeaders = new ArrayList<>();
									for (HttpHeader header : headers) {
										String headerString = replacement.getPattern().matcher(header.toString()).replaceAll(replacement.getReplace());
										// If header is now empty, we don't add it back into the request.
										if (!headerString.isEmpty()) {
											// If header has changed, update the header in the request.
											if (!headerString.equals(header.toString())) {
												updatedHeaders.add(HttpHeader.httpHeader(headerString));
											} else {
												updatedHeaders.add(header);
											}
										}

										// We have to remove each header individually and then add them back later to preserve the order.
										httpRequest = httpRequest.withRemovedHeader(header);
									}

									for (HttpHeader header : updatedHeaders) {
										httpRequest = httpRequest.withAddedHeader(header);
									}
									break;
								}
								// Request Header Name
								case 7 -> {
									List<HttpHeader> headers = httpRequest.headers();
									List<HttpHeader> updatedHeaders = new ArrayList<>();
									for (HttpHeader header : headers) {
										String headerNameString = replacement.getPattern().matcher(header.name()).replaceAll(replacement.getReplace());
										// If header name is now empty, we don't add it back into the request.
										if (!headerNameString.isEmpty()) {
											// If header name has changed, update the header in the request.
											if (!headerNameString.equals(header.name())) {
												updatedHeaders.add(HttpHeader.httpHeader(headerNameString, header.value()));
											} else {
												updatedHeaders.add(header);
											}
										}

										// We have to remove each header individually and then add them back later to preserve the order.
										httpRequest = httpRequest.withRemovedHeader(header);
									}

									for (HttpHeader header : updatedHeaders) {
										httpRequest = httpRequest.withAddedHeader(header);
									}
									break;
								}
								// Request Header Value
								case 8 -> {
									List<HttpHeader> headers = httpRequest.headers();
									for (HttpHeader header : headers) {
										String headerValueString = replacement.getPattern().matcher(header.value()).replaceAll(replacement.getReplace());

										// If header value has changed, update the header in the request
										// Empty values are technically OK.
										if (!headerValueString.equals(header.value())) {
											httpRequest = httpRequest.withUpdatedHeader(header.name(), headerValueString);
										}
									}
									break;
								}
								// Request Body
								case 9 -> {
									httpRequest = httpRequest.withBody(replacement.getPattern().matcher(httpRequest.bodyToString()).replaceAll(replacement.getReplace()));
									// Since the Content-Length header gets updated automatically, we should reset it unless the user has
									// specified otherwise.
									if (!this.updateRequestContentLength && requestContentLength != null) {
										httpRequest = httpRequest.withUpdatedHeader("Content-Length", requestContentLength.toString());
									}
									break;
								}
								// Request Body Params
								case 10 -> {
									String entireRequest = httpRequest.toByteArray().toString();
									List<ParsedHttpParameter> params = httpRequest.parameters();
									List<HttpParameter> updatedParams = new ArrayList<>();
									for (ParsedHttpParameter param : params) {
										// JSON parameters are incompatible, maybe XML is to? TODO: check
										if (param.type().equals(HttpParameterType.JSON)) {
											continue;
										}
										if (param.type().equals(HttpParameterType.BODY))
										{
											String paramString = replacement.getPattern().matcher(entireRequest.substring(param.nameOffsets().startIndexInclusive(), param.valueOffsets().endIndexExclusive())).replaceAll(replacement.getReplace());
											// If param is now empty, we don't add it back to the request.
											if (!paramString.isEmpty()) {
												String[] keyValue = paramString.split("=", 2);
												if (keyValue.length == 2) {
													updatedParams.add(HttpParameter.bodyParameter(keyValue[0], keyValue[1]));
												} else if (keyValue.length == 1) {
													updatedParams.add(HttpParameter.bodyParameter(keyValue[0], ""));
												}
											}
										} else {
											updatedParams.add(param);
										}

										// We have to remove each param individually and then add them back later for some reason.
										httpRequest = httpRequest.withRemovedParameters(param);
									}

									httpRequest = httpRequest.withAddedParameters(updatedParams);
									
									// Since the Content-Length header gets updated automatically, we should reset it unless the user has
									// specified otherwise.
									if (!this.updateRequestContentLength && requestContentLength != null) {
										httpRequest = httpRequest.withUpdatedHeader("Content-Length", requestContentLength.toString());
									}
									break;
								}
								// Request Body Param Name
								case 11 -> {
									List<ParsedHttpParameter> params = httpRequest.parameters();
									List<HttpParameter> updatedParams = new ArrayList<>();
									for (ParsedHttpParameter param : params) {
										if (param.type().equals(HttpParameterType.BODY)) {
											String paramName = replacement.getPattern().matcher(param.name()).replaceAll(replacement.getReplace());
											// If param name is now empty, we don't add it back to the request.
											if (!paramName.isEmpty()) {
												updatedParams.add(HttpParameter.bodyParameter(paramName, param.value()));
											}
										} else {
											updatedParams.add(param);
										}

										// We have to remove each param individually and then add them back later for some reason.
										httpRequest = httpRequest.withRemovedParameters(param);
									}

									httpRequest = httpRequest.withAddedParameters(updatedParams);	
									
									// Since the Content-Length header gets updated automatically, we should reset it unless the user has
									// specified otherwise.
									if (!this.updateRequestContentLength && requestContentLength != null) {
										httpRequest = httpRequest.withUpdatedHeader("Content-Length", requestContentLength.toString());
									}
									break;
								}
								// Request Body Param Value
								case 12 -> {
									List<ParsedHttpParameter> params = httpRequest.parameters();
									List<HttpParameter> updatedParams = new ArrayList<>();
									for (ParsedHttpParameter param : params) {
										if (param.type().equals(HttpParameterType.BODY)) {
											String paramValue = replacement.getPattern().matcher(param.value()).replaceAll(replacement.getReplace());
											updatedParams.add(HttpParameter.bodyParameter(param.name(), paramValue));
										} else {
											updatedParams.add(param);
										}

										// We have to remove each param individually and then add them back later for some reason.
										httpRequest = httpRequest.withRemovedParameters(param);
									}
									httpRequest = httpRequest.withAddedParameters(updatedParams);
									
									// Since the Content-Length header gets updated automatically, we should reset it unless the user has
									// specified otherwise.
									if (!this.updateRequestContentLength && requestContentLength != null) {
										httpRequest = httpRequest.withUpdatedHeader("Content-Length", requestContentLength.toString());
									}
									break;
								}

								default -> {break;}
							}
						} catch (IndexOutOfBoundsException ex) {							
							Logger.getLogger().logToError("An exception occurred when trying to execute a copy rule on a request: " + ex.getMessage());
							Logger.getLogger().logToError("This usually means your replacement referenced a group which didn't exist in the match.");
							Logger.getLogger().logToError("Replacement: " + replacement.toString(requestRulesTableModel.getLocations()) + "\n");
						}
					}
				}
			}

			// Sometimes (e.g. in a Repeater tab) there won't be a response.
			if (replaceResponse && httpResponse != null) {

				Integer responseContentLength = null;
				for (HttpHeader h : httpResponse.headers()) {
					if (h.name().trim().equalsIgnoreCase("Content-Length")) {
						try {
							responseContentLength = Integer.parseInt(h.value().trim());
						} catch (NumberFormatException e) {}

						break;
					}
				}

				// Figure out what line breaks are used for headers.
				String headersString = new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8).substring(0, httpResponse.bodyOffset());
				String linebreak = "\r\n";
				if (!headersString.contains(linebreak)) {
					linebreak = "\n";
				}

				for (Rule replacement : this.getResponseRulesTableModel().getData()) {
					if (replacement.isEnabled()) {
						try {
							switch (replacement.getLocation()) {
								// Entire Response
								case 0 -> {
									String entireResponse = new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8);
									httpResponse = HttpResponse.httpResponse(replacement.getPattern().matcher(entireResponse).replaceAll(replacement.getReplace()));
									break;
								}
								// Response Status Line
								case 1 -> {
									String[] entireResponseAsArray = (new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8)).lines().toList().toArray(new String[0]);
									if (entireResponseAsArray.length > 0) {
										entireResponseAsArray[0] = replacement.getPattern().matcher(entireResponseAsArray[0]).replaceAll(replacement.getReplace());
									} else {
										break;
									}
									httpResponse = HttpResponse.httpResponse(String.join("\r\n", entireResponseAsArray));
									break;
								}
								// Response Headers
								case 2 -> {
									String statusLine = getFirstLine(httpResponse);
									if (statusLine == null) {
										break;
									}

									List<HttpHeader> headers = httpResponse.headers();
									StringBuilder sb = new StringBuilder();
									for (HttpHeader header : headers) {
										sb.append(header.toString()).append(linebreak);
									}

									String updatedHeaders = replacement.getPattern().matcher(sb.toString()).replaceAll(replacement.getReplace());
									while (updatedHeaders.contains("\r\n\r\n") || updatedHeaders.contains("\n\n")) {
										updatedHeaders = updatedHeaders.replace("\r\n\r\n", "\r\n").replace("\n\n", "\n");
									}

									httpResponse = HttpResponse.httpResponse(statusLine + linebreak + updatedHeaders + linebreak + httpResponse.bodyToString());
									break;
								}
								// Response Header
								case 3 -> {
									String statusLine = getFirstLine(httpResponse);
									if (statusLine == null) {
										break;
									}

									List<HttpHeader> headers = httpResponse.headers();
									List<HttpHeader> updatedHeaders = new ArrayList<>();
									for (HttpHeader header : headers) {
										String headerString = replacement.getPattern().matcher(header.toString()).replaceAll(replacement.getReplace());
										// If header is now empty, we don't add it back into the request.
										if (!headerString.isEmpty()) {
											// If header has changed, update the header in the request.
											if (!headerString.equals(header.toString())) {
												updatedHeaders.add(HttpHeader.httpHeader(headerString));
											} else {
												updatedHeaders.add(header);
											}
										}
									}

									StringBuilder sb = new StringBuilder();
									for (HttpHeader header : updatedHeaders) {
										sb.append(header.toString()).append(linebreak);
									}

									httpResponse = HttpResponse.httpResponse(statusLine + linebreak + sb.toString() + linebreak + httpResponse.bodyToString());
									break;
								}
								// Response Header Name
								case 4 -> {
									String statusLine = getFirstLine(httpResponse);
									if (statusLine == null) {
										break;
									}

									List<HttpHeader> headers = httpResponse.headers();
									List<HttpHeader> updatedHeaders = new ArrayList<>();
									for (HttpHeader header : headers) {
										String headerNameString = replacement.getPattern().matcher(header.name()).replaceAll(replacement.getReplace());
										// If header name is now empty, we don't add it back into the request.
										if (!headerNameString.isEmpty()) {
											// If header name has changed, update the header in the request.
											if (!headerNameString.equals(header.name())) {
												updatedHeaders.add(HttpHeader.httpHeader(headerNameString, header.value()));
											} else {
												updatedHeaders.add(header);
											}
										}
									}

									StringBuilder sb = new StringBuilder();
									for (HttpHeader header : updatedHeaders) {
										sb.append(header.toString()).append(linebreak);
									}

									httpResponse = HttpResponse.httpResponse(statusLine + linebreak + sb.toString() + linebreak + httpResponse.bodyToString());
									break;
								}
								// Response Header Value
								case 5 -> {
									String statusLine = getFirstLine(httpResponse);
									if (statusLine == null) {
										break;
									}

									List<HttpHeader> headers = httpResponse.headers();
									List<HttpHeader> updatedHeaders = new ArrayList<>();
									for (HttpHeader header : headers) {
										String headerValueString = replacement.getPattern().matcher(header.value()).replaceAll(replacement.getReplace());

										// If header value has changed, update the header in the request
										// Empty values are technically OK.
										if (!headerValueString.equals(header.value())) {
											updatedHeaders.add(HttpHeader.httpHeader(header.name(), headerValueString));
										} else {
											updatedHeaders.add(header);
										}
									}

									StringBuilder sb = new StringBuilder();
									for (HttpHeader header : updatedHeaders) {
										sb.append(header.toString()).append(linebreak);
									}

									httpResponse = HttpResponse.httpResponse(statusLine + linebreak + sb.toString() + linebreak + httpResponse.bodyToString());
									break;
								}
								// Response Body
								case 6 -> {
									httpResponse = httpResponse.withBody(replacement.getPattern().matcher(httpResponse.bodyToString()).replaceAll(replacement.getReplace()));
									
									if (!this.updateResponseContentLength && responseContentLength != null) {
										httpResponse = httpResponse.withUpdatedHeader("Content-Length", responseContentLength.toString());
									}
									break;
								}

								default -> {break;}
							}
						} catch (IndexOutOfBoundsException ex) {
							Logger.getLogger().logToError("An exception occurred when trying to execute a copy rule on a response: " + ex.getMessage());
							Logger.getLogger().logToError("This usually means your replacement referenced a group which didn't exist in the match.");
							Logger.getLogger().logToError("Replacement: " + replacement.toString(responseRulesTableModel.getLocations()) + "\n");
						}
					}
				}
			}
			
			// If request was HTTP/2 originally, convert back.
			if (isHTTP2) {
				// Need to build URL param list manually.
				ArrayList<HttpParameter> queryParams = new ArrayList<HttpParameter>();
				for (HttpParameter p : httpRequest.parameters()) {
					if (p.type().equals(HttpParameterType.URL)) {
						queryParams.add(p);
					}
				}

				HttpRequest http2 = HttpRequest.http2Request(httpRequest.httpService(), httpRequest.headers(), httpRequest.body());
				// Make sure the request includes the correct method, path, and URL params.
				httpRequest = http2.withMethod(httpRequest.method()).withPath(httpRequest.path()).withRemovedParameters(queryParams).withAddedParameters(queryParams);
			}
			
			modified.add(HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse));
		}

		return modified;
	}
}
