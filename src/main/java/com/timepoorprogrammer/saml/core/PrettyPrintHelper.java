package com.timepoorprogrammer.saml.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;

/**
 * This class "pretty prints" an XML stream to something more human-readable
 * for file or for log output.
 * <p/>
 * Its only ever used to dump the contents of a SAML message to file or log,
 * and not for SAML message transport.
 * <p/>
 * It duplicates the character content with some modifications to whitespace,
 * restoring line breaks and a simple pattern of indenting child elements.
 * <p/>
 * This version of the class acts as a SAX 2.0 <code>DefaultHandler</code>,
 * so to provide the unformatted XML just pass a new instance to a SAX parser.
 * Its output is via the {@link #toString toString} method.
 * <p/>
 * One major limitation:  it gathers character data for elements in a single
 * buffer, so mixed-content documents will lose a lot of data!  This works
 * best with data-centric documents where elements either have single values
 * or child elements, but not both.
 *
 * @author Jim Ball (completely borrowed from Will Provost for file or log printing)
 */
public class PrettyPrintHelper extends DefaultHandler {
    /**
     * Logging handle
     */
    private static final Logger log = LoggerFactory.getLogger(PrettyPrintHelper.class);
    /**
     * Namsepace prefix details
     */
    private static final String NAMESPACE_PREFIXES = "http://xml.org/sax/features/namespace-prefixes";
    /**
     * XML document start
     */
    private static final String XML_START = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>";


    /**
     * Helper method to pretty-print or ugly print any DOM node (element or document)
     * to a file or to log.
     *
     * @param node     node
     * @param filename filename or null (meaning write to log)
     */
    public static void printToFile(Node node, String filename) {
        try {
            final String result = PrettyPrintHelper.prettyPrint(node);
            if (filename != null) {
                PrintWriter writer = new PrintWriter(new FileWriter(filename));
                writer.println(result);
                writer.close();
            } else {
                log.debug(result);
            }
        } catch (Exception anyE) {
            final String errorMessage = "Error printing contents of XMLObject to file";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Convenience method to wrap pretty-printing SAX pass over existing byte content.
     *
     * @param content Byte content to print
     * @return pretty version
     */
    public static String prettyPrint(byte[] content) {
        try {
            PrettyPrintHelper pretty = new PrettyPrintHelper();
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setFeature(NAMESPACE_PREFIXES, true);
            factory.newSAXParser().parse(new ByteArrayInputStream(content), pretty);
            return pretty.toString();
        }
        catch (Exception ex) {
            final String errorMessage = "Error pretty printing byte content";
            log.error(errorMessage, ex);
            throw new RuntimeException(errorMessage, ex);
        }
    }

    /**
     * Convenience method to wrap pretty-printing SAX pass over existing string content.
     *
     * @param content String content to print
     * @return pretty version
     */
    public static String prettyPrint(String content) {
        try {
            PrettyPrintHelper pretty = new PrettyPrintHelper();
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setFeature(NAMESPACE_PREFIXES, true);
            factory.newSAXParser().parse(content, pretty);
            return pretty.toString();
        }
        catch (Exception anyE) {
            final String errorMessage = "Error pretty printing string content";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Convenience method to wrap pretty-printing SAX pass over existing content.
     *
     * @param content Content to print
     * @return pretty version
     */
    public static String prettyPrint(InputStream content) {
        try {
            PrettyPrintHelper pretty = new PrettyPrintHelper();
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setFeature(NAMESPACE_PREFIXES, true);
            factory.newSAXParser().parse(content, pretty);
            return pretty.toString();
        }
        catch (Exception anyE) {
            final String errorMessage = "Error pretty printing input stream content";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Convenience method to wrap pretty-printing SAX pass over existing XML.
     *
     * @param node HTML node to print
     * @return pretty version
     * @throws TransformerException on transformation error
     */
    public static String prettyPrint(Node node) throws TransformerException {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            TransformerFactory.newInstance().newTransformer().transform(new DOMSource(node), new StreamResult(buffer));
            byte[] rawResult = buffer.toByteArray();
            buffer.close();
            return prettyPrint(rawResult);
        }
        catch (Exception anyE) {
            final String errorMessage = "Error pretty printing node content";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Call this to get the formatted XML post-parsing.
     */
    public String toString() {
        return output.toString();
    }

    /**
     * Prints the XML declaration.
     */
    public void startDocument() throws SAXException {
        output.append(XML_START).append(endLine);
    }

    /**
     * Prints a blank line at the end of the reformatted document.
     */
    public void endDocument() throws SAXException {
        output.append(endLine);
    }

    /**
     * Writes the start tag for the element.
     * Attributes are written out, one to a text line.  Starts gathering
     * character data for the element.
     */
    public void startElement
            (String URI, String name, String qName, Attributes attributes)
            throws SAXException {
        if (justHitStartTag)
            output.append('>');

        output.append(endLine)
                .append(indent)
                .append('<')
                .append(qName);

        int length = attributes.getLength();
        for (int a = 0; a < length; ++a)
            output.append(endLine)
                    .append(indent)
                    .append(standardIndent)
                    .append(attributes.getQName(a))
                    .append("=\"")
                    .append(attributes.getValue(a))
                    .append('\"');

        if (length > 0)
            output.append(endLine)
                    .append(indent);

        indent += standardIndent;
        currentValue = new StringBuffer();
        justHitStartTag = true;
    }

    /**
     * Checks the {@link #currentValue} buffer to gather element content.
     * Writes this out if it is available.  Writes the element end tag.
     */
    public void endElement(String URI, String name, String qName)
            throws SAXException {
        indent = indent.substring
                (0, indent.length() - standardIndent.length());

        if (currentValue == null)
            output.append(endLine)
                    .append(indent)
                    .append("</")
                    .append(qName)
                    .append('>');
        else if (currentValue.length() != 0)
            output.append('>')
                    .append(currentValue.toString())
                    .append("</")
                    .append(qName)
                    .append('>');
        else
            output.append("/>");

        currentValue = null;
        justHitStartTag = false;
    }

    /**
     * When the {@link #currentValue} buffer is enabled, appends character
     * data into it, to be gathered when the element end tag is encountered.
     */
    public void characters(char[] chars, int start, int length)
            throws SAXException {
        if (currentValue != null)
            currentValue.append(escape(chars, start, length));
    }

    /**
     * Filter to pass strings to output, escaping <b>&lt;</b> and <b>&amp;</b>
     * characters to &amp;lt; and &amp;amp; respectively.
     *
     * @param chars  chars
     * @param start  start
     * @param length length
     * @return escaped string
     */
    private static String escape(char[] chars, int start, int length) {
        StringBuffer result = new StringBuffer();
        for (int c = start; c < start + length; ++c)
            if (chars[c] == '<')
                result.append("&lt;");
            else if (chars[c] == '&')
                result.append("&amp;");
            else
                result.append(chars[c]);

        return result.toString();
    }

    /**
     * This whitespace string is expanded and collapsed to manage the output
     * indenting.
     */
    private String indent = "";

    /**
     * A buffer for character data.  It is &quot;enabled&quot; in
     * {@link #startElement startElement} by being initialized to a
     * new <b>StringBuffer</b>, and then read and reset to
     * <code>null</code> in {@link #endElement endElement}.
     */
    private StringBuffer currentValue = null;

    /**
     * The primary buffer for accumulating the formatted XML.
     */
    private StringBuffer output = new StringBuffer();

    private boolean justHitStartTag;
    private static final String standardIndent = "  ";
    private static final String endLine = System.getProperty("line.separator");
}

